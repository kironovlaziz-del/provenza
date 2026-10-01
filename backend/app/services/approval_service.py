from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from typing import List, Optional
from app.models.ai_approval import AIApproval
from app.models.ai_request import AIRequest
from app.models.ai_use_case import AIUseCase
from app.models.ai_policy import AIPolicyVersion
from app.models.user import User, UserRole
from app.schemas.approval import ApprovalCreate, ApprovalDecision


class ApprovalService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _pick_approver(
        self, org_id: int, use_case: Optional[AIUseCase], caller_user_id: int
    ) -> int:
        """
        Determine who should approve a given request.

        Priority:
          1. If the use case links an approved policy version whose rules
             name an "approver_user_id", use that user (if still active).
          2. If the caller is themselves an approver, use them.
          3. Otherwise pick any active approver in the organization.
          4. Only if no approvers exist, fall back to the caller if admin.
          5. Last resort: any active admin in the organization.
          6. Otherwise 400.

        This ordering means an admin creating a request does not silently
        assign themselves as approver when there is a real approver on the
        team who can do it.
        """
        # 1. Policy-driven approver
        if use_case and use_case.approved_policy_version_id:
            result = await self.db.execute(
                select(AIPolicyVersion).where(
                    AIPolicyVersion.id == use_case.approved_policy_version_id
                )
            )
            policy_version = result.scalar_one_or_none()
            if policy_version:
                rules = policy_version.rules_json or {}
                configured_id = rules.get("approver_user_id")
                if isinstance(configured_id, int):
                    result = await self.db.execute(
                        select(User).where(
                            User.id == configured_id,
                            User.org_id == org_id,
                            User.status == "active",
                            User.role.in_(
                                [UserRole.admin.value, UserRole.approver.value]
                            ),
                        )
                    )
                    if result.scalar_one_or_none():
                        return configured_id

        # 2. Caller is an approver
        result = await self.db.execute(
            select(User).where(
                User.id == caller_user_id,
                User.status == "active",
                User.role == UserRole.approver.value,
            )
        )
        if result.scalar_one_or_none():
            return caller_user_id

        # 3. Any active approver in the organization
        result = await self.db.execute(
            select(User)
            .where(
                User.org_id == org_id,
                User.status == "active",
                User.role == UserRole.approver.value,
            )
            .order_by(User.id.asc())
            .limit(1)
        )
        picked = result.scalar_one_or_none()
        if picked:
            return picked.id

        # 4. Caller is admin (only when no approvers exist)
        result = await self.db.execute(
            select(User).where(
                User.id == caller_user_id,
                User.status == "active",
                User.role == UserRole.admin.value,
            )
        )
        if result.scalar_one_or_none():
            return caller_user_id

        # 5. Any active admin in the organization
        result = await self.db.execute(
            select(User)
            .where(
                User.org_id == org_id,
                User.status == "active",
                User.role == UserRole.admin.value,
            )
            .order_by(User.id.asc())
            .limit(1)
        )
        picked = result.scalar_one_or_none()
        if picked:
            return picked.id

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "No approver available: this organization has no active "
                "approver or admin, and the policy does not name one."
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

        approver_id = await self._pick_approver(org_id, use_case, caller_user_id)

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
