from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from typing import List, Optional
from app.models.ai_approval import AIApproval
from app.models.ai_request import AIRequest
from app.models.ai_use_case import AIUseCase
from app.models.ai_policy import AIPolicy, AIPolicyVersion
from app.models.user import User, UserRole
from app.schemas.approval import ApprovalCreate, ApprovalDecision


class ApprovalService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _active_with_role(self, org_id: int, user_id: int, roles: List[str]) -> bool:
        return (await self.db.execute(select(User.id).where(
            User.id == user_id, User.org_id == org_id, User.status == "active", User.role.in_(roles),
        ))).scalar_one_or_none() is not None

    async def _first_with_role(self, org_id: int, role: str, exclude: Optional[int]) -> Optional[int]:
        q = select(User.id).where(User.org_id == org_id, User.status == "active", User.role == role)
        if exclude is not None:
            q = q.where(User.id != exclude)
        return (await self.db.execute(q.order_by(User.id.asc()).limit(1))).scalar_one_or_none()

    async def _pick_approver(
        self, org_id: int, use_case: Optional[AIUseCase], caller_user_id: int,
        requester_id: Optional[int] = None,
    ) -> int:
        """
        Who approves a request. Never the person who made it (four eyes):

          1. the approver the use case's approved policy names (if still active);
          2. the caller, if an approver;
          3. any active approver;
          4. the caller, if an admin;
          5. any active admin;
          6. otherwise 400 - add a second approver or admin.
        """
        admin_or_approver = [UserRole.admin.value, UserRole.approver.value]

        def other(uid: Optional[int]) -> bool:
            return uid is not None and uid != requester_id

        # 1. Policy-driven approver
        if use_case and use_case.approved_policy_version_id:
            result = await self.db.execute(
                select(AIPolicyVersion)
                .join(AIPolicy, AIPolicy.id == AIPolicyVersion.policy_id)
                .where(
                    AIPolicyVersion.id == use_case.approved_policy_version_id,
                    AIPolicy.org_id == org_id,
                )
            )
            policy_version = result.scalar_one_or_none()
            if policy_version:
                configured_id = (policy_version.rules_json or {}).get("approver_user_id")
                if isinstance(configured_id, int) and other(configured_id) and \
                        await self._active_with_role(org_id, configured_id, admin_or_approver):
                    return configured_id

        # 2. Caller is an approver
        if other(caller_user_id) and await self._active_with_role(org_id, caller_user_id, [UserRole.approver.value]):
            return caller_user_id
        # 3. Any active approver
        picked = await self._first_with_role(org_id, UserRole.approver.value, requester_id)
        if picked is not None:
            return picked
        # 4. Caller is an admin
        if other(caller_user_id) and await self._active_with_role(org_id, caller_user_id, [UserRole.admin.value]):
            return caller_user_id
        # 5. Any active admin
        picked = await self._first_with_role(org_id, UserRole.admin.value, requester_id)
        if picked is not None:
            return picked

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "No approver available: a request is approved by someone other than "
                "the person who made it - add another approver or admin."
            ),
        )

    async def create_approval(
        self, org_id: int, caller_user_id: int, data: ApprovalCreate
    ) -> AIApproval:
        result = await self.db.execute(
            select(AIRequest).where(
                AIRequest.id == data.request_id,
                AIRequest.org_id == org_id,
            )
        )
        request = result.scalar_one_or_none()
        if not request:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Request not found",
            )

        # Guard against duplicate approvals for the same request.
        result = await self.db.execute(
            select(AIApproval).where(
                AIApproval.request_id == data.request_id,
                AIApproval.decision.is_(None),
            )
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This request already has a pending approval.",
            )

        use_case = None
        if request.use_case_id:
            result = await self.db.execute(
                select(AIUseCase).where(AIUseCase.id == request.use_case_id)
            )
            use_case = result.scalar_one_or_none()

        # Only a request that is waiting for approval: one the firewall blocked,
        # or one already run, is not turned into an approvable one.
        if request.status != "pending_approval":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Only a request waiting for approval can be sent to an approver (this one is {request.status}).",
            )

        approver_id = await self._pick_approver(org_id, use_case, caller_user_id, request.user_id)

        approval = AIApproval(
            request_id=data.request_id,
            approver_user_id=approver_id,
        )
        self.db.add(approval)

        request.status = "pending_approval"

        await self.db.commit()
        await self.db.refresh(approval)
        return approval

    async def make_decision(
        self,
        approval_id: int,
        org_id: int,
        caller_user: User,
        data: ApprovalDecision,
    ) -> AIApproval:
        result = await self.db.execute(
            select(AIApproval).join(AIRequest).where(
                AIApproval.id == approval_id,
                AIRequest.org_id == org_id,
            )
        )
        approval = result.scalar_one_or_none()
        if not approval:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Approval not found",
            )

        # Four eyes: nobody decides on their own request, admins included.
        requester_id = (await self.db.execute(
            select(AIRequest.user_id).where(AIRequest.id == approval.request_id)
        )).scalar_one_or_none()
        if requester_id is not None and requester_id == caller_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You cannot decide on your own request.",
            )

        # Only the assigned approver (or an admin) may decide.
        is_assigned = approval.approver_user_id == caller_user.id
        is_admin = caller_user.role == UserRole.admin.value
        if not (is_assigned or is_admin):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the assigned approver can decide this request.",
            )

        if approval.decision is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This approval has already been decided.",
            )

        approval.decision = data.decision
        approval.reason = data.reason

        result = await self.db.execute(
            select(AIRequest).where(AIRequest.id == approval.request_id)
        )
        request = result.scalar_one_or_none()
        if request:
            request.status = "approved" if data.decision == "approved" else "rejected"

        await self.db.commit()
        await self.db.refresh(approval)

        if request and data.decision == "approved":
            # Hand off to Celery - the provider call can take up to a
            # minute and would block the HTTP response otherwise.
            from app.core.celery_app import celery_app

            from app.services.queue_ttl import enqueue_request
            await enqueue_request(self.db, request, org_id)

        return approval

    async def list_approvals(
        self, org_id: int, skip: int = 0, limit: int = 50
    ) -> "tuple[List[AIApproval], int]":
        from sqlalchemy import func

        base = (
            select(AIApproval)
            .join(AIRequest)
            .where(AIRequest.org_id == org_id)
        )
        total = await self.db.scalar(
            select(func.count()).select_from(base.subquery())
        )
        result = await self.db.execute(
            base.order_by(AIApproval.created_at.desc()).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)
