-- Provenza demo data seed
DO $$
DECLARE
    v_org_id INTEGER;
    v_admin_id INTEGER;
    v_admin_hash TEXT;
    v_p_openai INTEGER;
    v_p_anthropic INTEGER;
    v_p_azure INTEGER;
    v_p_groq INTEGER;
    v_p_ollama INTEGER;
    v_pol1 INTEGER;
    v_pol2 INTEGER;
    v_pol3 INTEGER;
    v_ing INTEGER;
    v_ag1 INTEGER;
    v_ag2 INTEGER;
    v_ag3 INTEGER;
    v_chain1 INTEGER;
    v_chain2 INTEGER;
    v_req_id INTEGER;
    i INTEGER;
BEGIN
    SELECT id INTO v_org_id FROM organizations WHERE slug='demo';
    IF v_org_id IS NULL THEN RAISE EXCEPTION 'Demo org not found'; END IF;
    SELECT id, hashed_password INTO v_admin_id, v_admin_hash FROM users WHERE email='admin@demo.com';
    IF (SELECT COUNT(*) FROM shadow_ai_sightings WHERE org_id=v_org_id) > 0 THEN
        RAISE NOTICE 'Demo data already exists — skipping'; RETURN;
    END IF;

    -- === USERS ===
    INSERT INTO users (org_id, email, name, hashed_password, role, status, ui_mode) VALUES
      (v_org_id,'ivan.petrov@demo.com','Ivan Petrov',v_admin_hash,'user','active','user'),
      (v_org_id,'anna.smirnova@demo.com','Anna Smirnova',v_admin_hash,'user','active','user'),
      (v_org_id,'sergey.volkov@demo.com','Sergey Volkov',v_admin_hash,'auditor','active','user'),
      (v_org_id,'maria.kim@demo.com','Maria Kim',v_admin_hash,'user','active','user'),
      (v_org_id,'dmitry.orlov@demo.com','Dmitry Orlov',v_admin_hash,'user','active','user'),
      (v_org_id,'elena.sokolova@demo.com','Elena Sokolova',v_admin_hash,'compliance','active','user'),
      (v_org_id,'alexey.ivanov@demo.com','Alexey Ivanov',v_admin_hash,'user','active','user'),
      (v_org_id,'olga.petrova@demo.com','Olga Petrova',v_admin_hash,'user','active','user'),
      (v_org_id,'nikolay.fedorov@demo.com','Nikolay Fedorov',v_admin_hash,'user','active','user'),
      (v_org_id,'kate.novak@demo.com','Kate Novak',v_admin_hash,'user','active','user');

    -- === PROVIDERS ===
    INSERT INTO ai_providers (org_id,name,type,status,sla,risk_score,base_url,default_model)
      VALUES (v_org_id,'OpenAI','openai','active','99.9%',7.5,'https://api.openai.com/v1','gpt-4o') RETURNING id INTO v_p_openai;
    INSERT INTO ai_providers (org_id,name,type,status,sla,risk_score,base_url,default_model)
      VALUES (v_org_id,'Anthropic','anthropic','active','99.9%',7.0,'https://api.anthropic.com','claude-sonnet-4') RETURNING id INTO v_p_anthropic;
    INSERT INTO ai_providers (org_id,name,type,status,sla,risk_score,base_url,default_model)
      VALUES (v_org_id,'Azure OpenAI','azure_openai','active','99.95%',8.0,'https://demo.openai.azure.com','gpt-4o') RETURNING id INTO v_p_azure;
    INSERT INTO ai_providers (org_id,name,type,status,sla,risk_score,base_url,default_model)
      VALUES (v_org_id,'Groq','groq','active','99.5%',6.5,'https://api.groq.com/openai/v1','llama-3.3-70b') RETURNING id INTO v_p_groq;
    INSERT INTO ai_providers (org_id,name,type,status,sla,risk_score,base_url,default_model)
      VALUES (v_org_id,'Ollama (local)','ollama','active','N/A',4.0,'http://localhost:11434/v1','llama3.2') RETURNING id INTO v_p_ollama;

    -- === DOMAIN CATALOG ===
    INSERT INTO ai_domain_catalog (org_id,domain,tool_name,category,policy_status,source) VALUES
      (v_org_id,'chat.openai.com','ChatGPT','llm','allow','builtin'),
      (v_org_id,'chatgpt.com','ChatGPT','llm','allow','builtin'),
      (v_org_id,'claude.ai','Claude','llm','allow','builtin'),
      (v_org_id,'gemini.google.com','Gemini','llm','allow','builtin'),
      (v_org_id,'api.openai.com','OpenAI API','api','allow','builtin'),
      (v_org_id,'api.anthropic.com','Anthropic API','api','allow','builtin'),
      (v_org_id,'api.groq.com','Groq API','api','allow','builtin'),
      (v_org_id,'perplexity.ai','Perplexity','search','unknown','builtin'),
      (v_org_id,'midjourney.com','Midjourney','image','block','builtin'),
      (v_org_id,'leonardo.ai','Leonardo AI','image','block','builtin'),
      (v_org_id,'cursor.com','Cursor','code','allow','builtin'),
      (v_org_id,'deepseek.com','DeepSeek','llm','unknown','builtin'),
      (v_org_id,'kimi.moonshot.cn','Kimi','llm','unknown','builtin'),
      (v_org_id,'ollama.com','Ollama','local','allow','builtin'),
      (v_org_id,'lmstudio.ai','LM Studio','local','unknown','builtin'),
      (v_org_id,'openrouter.ai','OpenRouter','api','unknown','builtin'),
      (v_org_id,'huggingface.co','Hugging Face','mlops','allow','builtin'),
      (v_org_id,'replicate.com','Replicate','api','unknown','builtin'),
      (v_org_id,'together.ai','Together AI','api','unknown','builtin'),
      (v_org_id,'elevenlabs.io','ElevenLabs','audio','block','builtin'),
      (v_org_id,'suno.com','Suno','music','unknown','builtin'),
      (v_org_id,'runwayml.com','Runway','video','block','builtin'),
      (v_org_id,'pika.art','Pika','video','unknown','builtin'),
      (v_org_id,'otter.ai','Otter.ai','audio','allow','builtin'),
      (v_org_id,'fireflies.ai','Fireflies','audio','unknown','builtin'),
      (v_org_id,'phind.com','Phind','code','unknown','builtin'),
      (v_org_id,'you.com','You.com','search','unknown','builtin'),
      (v_org_id,'groq.com','Groq','llm','allow','builtin'),
      (v_org_id,'mistral.ai','Mistral','llm','unknown','builtin'),
      (v_org_id,'cohere.com','Cohere','llm','unknown','builtin');

    -- === POLICIES ===
    INSERT INTO ai_policies (org_id,name,description,status)
      VALUES (v_org_id,'PII Protection','Blocks prompts with unmasked PII from reaching external providers','active')
      RETURNING id INTO v_pol1;
    INSERT INTO ai_policy_versions (policy_id,version,rules_json,created_by,approved_by,approved_at)
      VALUES (v_pol1,1,'{"rules":[{"type":"mask","targets":["EMAIL","PHONE","CARD","SSN","APIKEY"]},{"type":"block","terms":["password","secret"]}]}'::jsonb,
              v_admin_id,v_admin_id,now()-interval '30 days');

    INSERT INTO ai_policies (org_id,name,description,status)
      VALUES (v_org_id,'Shadow AI Detection','Detects unsanctioned AI tools on endpoints and network','active')
      RETURNING id INTO v_pol2;
    INSERT INTO ai_policy_versions (policy_id,version,rules_json,created_by,approved_by,approved_at)
      VALUES (v_pol2,1,'{"rules":[{"type":"alert","tools":["chatgpt","claude","midjourney","elevenlabs"]},{"type":"block","domains":["midjourney.com","runwayml.com"]}]}'::jsonb,
              v_admin_id,v_admin_id,now()-interval '20 days');

    INSERT INTO ai_policies (org_id,name,description,status)
      VALUES (v_org_id,'Agent Delegation Controls','Enforces monotonic TTL and capability subsetting for AI agents','active')
      RETURNING id INTO v_pol3;
    INSERT INTO ai_policy_versions (policy_id,version,rules_json,created_by,approved_by,approved_at)
      VALUES (v_pol3,1,'{"rules":[{"type":"ttl_monotonic","max_depth":3},{"type":"capability_subset","enforce":true}]}'::jsonb,
              v_admin_id,v_admin_id,now()-interval '10 days');

    -- === INGESTION SOURCE ===
    INSERT INTO ingestion_sources (org_id,name,source_type,api_key_hash,enabled,created_by)
      VALUES (v_org_id,'Endpoint Agent — Demo','agent','demo-hash',true,v_admin_id)
      RETURNING id INTO v_ing;

    -- === AI REQUESTS (30) ===
    FOR i IN 1..30 LOOP
      INSERT INTO ai_requests (org_id,user_id,provider_id,input_text_encrypted,masked_input_text,purpose,risk_level,status,created_at,firewall_flags)
      VALUES (
        v_org_id,
        (SELECT id FROM users WHERE org_id=v_org_id AND email LIKE '%@demo.com' ORDER BY random() LIMIT 1),
        (ARRAY[v_p_openai,v_p_anthropic,v_p_azure,v_p_groq,v_p_ollama])[1+floor(random()*5)],
        'encrypted-input-'||i,
        'Please summarize the quarterly report for ' || (ARRAY['marketing','sales','engineering','hr','finance'])[1+floor(random()*5)],
        (ARRAY['summarization','code-review','translation','drafting','analysis'])[1+floor(random()*5)],
        (ARRAY['low','low','medium','medium','high','critical'])[1+floor(random()*6)],
        (ARRAY['completed','completed','completed','completed','blocked','pending_approval'])[1+floor(random()*6)],
        now() - (random()*interval '30 days'),
        (CASE WHEN random()<0.4 THEN '{"pii":["EMAIL","PHONE"]}'::jsonb WHEN random()<0.7 THEN '{"pii":["CARD"]}'::jsonb ELSE '{}'::jsonb END)
      ) RETURNING id INTO v_req_id;

      INSERT INTO ai_responses (request_id,response_text,confidence_score,created_at)
      VALUES (v_req_id,'Generated response #'||i, 0.7+random()*0.29, now()-(random()*interval '29 days'));
    END LOOP;

    -- === SHADOW AI SIGHTINGS (15) ===
    INSERT INTO shadow_ai_sightings (org_id,tool_name,domain,detected_via,user_hint,notes,status,seen_count,last_seen_at,created_at) VALUES
      (v_org_id,'ChatGPT','chat.openai.com','network','ivan.petrov@demo.com','Repeated access during work hours','new',12,now()-interval '1 hour',now()-interval '5 days'),
      (v_org_id,'Claude','claude.ai','endpoint','anna.smirnova@demo.com','Process detected: claude-cli','new',5,now()-interval '3 hours',now()-interval '3 days'),
      (v_org_id,'Midjourney','midjourney.com','network','maria.kim@demo.com','Blocked by policy','resolved',3,now()-interval '2 days',now()-interval '10 days'),
      (v_org_id,'Ollama (local)','localhost:11434','endpoint','dmitry.orlov@demo.com','Local LLM running on laptop','new',8,now()-interval '30 minutes',now()-interval '2 days'),
      (v_org_id,'Gemini','gemini.google.com','browser_extension','alexey.ivanov@demo.com','Pasted email in prompt','new',2,now()-interval '4 hours',now()-interval '1 day'),
      (v_org_id,'Perplexity','perplexity.ai','network','olga.petrova@demo.com','Corporate account not used','dismissed',1,now()-interval '7 days',now()-interval '7 days'),
      (v_org_id,'ElevenLabs','elevenlabs.io','network','nikolay.fedorov@demo.com','Voice synthesis of internal docs','new',4,now()-interval '5 hours',now()-interval '4 days'),
      (v_org_id,'Runway','runwayml.com','network','kate.novak@demo.com','Video generation — blocked','resolved',2,now()-interval '6 days',now()-interval '6 days'),
      (v_org_id,'DeepSeek','deepseek.com','network','ivan.petrov@demo.com','Chinese LLM — requires review','new',6,now()-interval '2 hours',now()-interval '3 days'),
      (v_org_id,'LM Studio','lmstudio.ai','endpoint','anna.smirnova@demo.com','Local model on personal device','new',3,now()-interval '8 hours',now()-interval '5 days'),
      (v_org_id,'Cursor','cursor.com','endpoint','sergey.volkov@demo.com','AI coding tool — approved','resolved',15,now()-interval '1 day',now()-interval '14 days'),
      (v_org_id,'Hugging Face','huggingface.co','network','maria.kim@demo.com','Model download from HF Hub','new',9,now()-interval '1 hour',now()-interval '2 days'),
      (v_org_id,'Otter.ai','otter.ai','browser_extension','dmitry.orlov@demo.com','Meeting transcription','new',4,now()-interval '6 hours',now()-interval '1 day'),
      (v_org_id,'Suno','suno.com','network','alexey.ivanov@demo.com','Music generation','dismissed',1,now()-interval '10 days',now()-interval '10 days'),
      (v_org_id,'Mistral','mistral.ai','network','elena.sokolova@demo.com','EU-based provider — pending','new',2,now()-interval '12 hours',now()-interval '2 days');

    -- === INCIDENTS (6) ===
    INSERT INTO ai_incidents (org_id,severity,category,summary,impact,root_cause,status,created_at) VALUES
      (v_org_id,'high','data_leak','Email with customer list sent to ChatGPT','PII exposure of 47 customers','Employee bypassed masking','resolved',now()-interval '12 days'),
      (v_org_id,'critical','policy_violation','Agent attempted privileged file access','Blocked by runtime policy','Compromised agent prompt','resolved',now()-interval '9 days'),
      (v_org_id,'medium','shadow_ai','Local Ollama instance on developer laptop','Model files on unmanaged device','No endpoint agent installed','investigating',now()-interval '4 days'),
      (v_org_id,'high','ttl_violation','Child agent attempted TTL extension','Escalation rejected','Signed payload integrity check','resolved',now()-interval '3 days'),
      (v_org_id,'medium','approval_bypass','Risky prompt skipped approval queue','Request sent without sign-off','Misconfigured policy priority','open',now()-interval '2 days'),
      (v_org_id,'low','quota','Groq API rate limit hit by batch job','Retries delayed 20 min','No backoff configured','resolved',now()-interval '1 day');

    -- === AGENTS (3) ===
    INSERT INTO agents (org_id,name,description,agent_type,version,owner_user_id,owner_team,capabilities,allowed_tools,allowed_models,max_delegation_depth,status,api_key_hash,public_key)
      VALUES (v_org_id,'marketing-assistant','Automates marketing reports','crewai','1.0.0',v_admin_id,'marketing',
        '["read_analytics","generate_text"]'::jsonb,'["openai.chat","google.analytics.read"]'::jsonb,'["gpt-4o-mini"]'::jsonb,2,'active','hash-mkt','ed25519:abc...') RETURNING id INTO v_ag1;
    INSERT INTO agents (org_id,name,description,agent_type,version,owner_user_id,owner_team,capabilities,allowed_tools,allowed_models,max_delegation_depth,status,api_key_hash,public_key)
      VALUES (v_org_id,'data-analyst','Pulls and analyzes datasets','langgraph','1.2.0',v_admin_id,'data',
        '["query_db","read_analytics"]'::jsonb,'["postgres.read","bigquery.read"]'::jsonb,'["gpt-4o"]'::jsonb,3,'active','hash-data','ed25519:def...') RETURNING id INTO v_ag2;
    INSERT INTO agents (org_id,name,description,agent_type,version,owner_user_id,owner_team,capabilities,allowed_tools,allowed_models,max_delegation_depth,status,api_key_hash,public_key)
      VALUES (v_org_id,'report-writer','Writes and formats reports','langgraph','1.0.0',v_admin_id,'data',
        '["generate_text"]'::jsonb,'["openai.chat"]'::jsonb,'["gpt-4o-mini"]'::jsonb,1,'active','hash-rw','ed25519:ghi...') RETURNING id INTO v_ag3;

    -- === DELEGATION CHAINS ===
    INSERT INTO delegation_chains (org_id,root_agent_id,root_task,status,total_hops,max_depth_reached,started_at,completed_at)
      VALUES (v_org_id,v_ag1,'Generate Q3 marketing report','completed',2,2,now()-interval '2 hours',now()-interval '1 hour') RETURNING id INTO v_chain1;
    INSERT INTO delegation_chains (org_id,root_agent_id,root_task,status,total_hops,max_depth_reached,started_at)
      VALUES (v_org_id,v_ag2,'Analyze customer churn data','active',1,1,now()-interval '20 minutes') RETURNING id INTO v_chain2;

    INSERT INTO delegation_hops (org_id,chain_id,from_agent_id,to_agent_id,depth,delegated_capabilities,task_description,expires_at,signature,verified,signed_payload)
      VALUES (v_org_id,v_chain1,v_ag1,v_ag2,1,'["read_analytics"]'::jsonb,'Fetch Q3 sales data',now()+interval '30 minutes','ed25519:hop1...',true,'{"expires_in":1800}'::jsonb);
    INSERT INTO delegation_hops (org_id,chain_id,from_agent_id,to_agent_id,depth,delegated_capabilities,task_description,expires_at,signature,verified,signed_payload)
      VALUES (v_org_id,v_chain1,v_ag2,v_ag3,2,'["generate_text"]'::jsonb,'Write the final report',now()+interval '15 minutes','ed25519:hop2...',true,'{"expires_in":900}'::jsonb);
    INSERT INTO delegation_hops (org_id,chain_id,from_agent_id,to_agent_id,depth,delegated_capabilities,task_description,expires_at,signature,verified,signed_payload)
      VALUES (v_org_id,v_chain2,v_ag2,v_ag3,1,'["generate_text"]'::jsonb,'Summarize churn findings',now()+interval '10 minutes','ed25519:hop3...',true,'{"expires_in":600}'::jsonb);

    -- === AGENT ACTIONS ===
    INSERT INTO agent_actions (org_id,chain_id,agent_id,action_type,tool_name,input_data,output_data,policy_check_result,reason,duration_ms,created_at) VALUES
      (v_org_id,v_chain1,v_ag1,'tool_call','openai.chat','{"model":"gpt-4o-mini"}'::jsonb,'{"status":"ok"}'::jsonb,'allowed',null,420,now()-interval '110 minutes'),
      (v_org_id,v_chain1,v_ag1,'delegate','agent.delegate','{"to":"data-analyst"}'::jsonb,jsonb_build_object('chain_id', v_chain1),'allowed',null,45,now()-interval '105 minutes'),
      (v_org_id,v_chain1,v_ag2,'tool_call','postgres.read','{"table":"sales"}'::jsonb,'{"rows":1247}'::jsonb,'allowed',null,180,now()-interval '100 minutes'),
      (v_org_id,v_chain1,v_ag2,'delegate','agent.delegate','{"to":"report-writer"}'::jsonb,jsonb_build_object('chain_id', v_chain1),'allowed',null,30,now()-interval '95 minutes'),
      (v_org_id,v_chain1,v_ag3,'tool_call','openai.chat','{"model":"gpt-4o-mini"}'::jsonb,'{"status":"ok"}'::jsonb,'allowed',null,890,now()-interval '90 minutes'),
      (v_org_id,v_chain1,v_ag3,'tool_call','stripe.charge','{"amount":100}'::jsonb,'{}'::jsonb,'denied','Capability escalation: report-writer cannot access financial APIs',5,now()-interval '85 minutes'),
      (v_org_id,v_chain2,v_ag2,'tool_call','bigquery.read','{"dataset":"churn"}'::jsonb,'{"rows":8453}'::jsonb,'allowed',null,420,now()-interval '15 minutes'),
      (v_org_id,v_chain2,v_ag3,'tool_call','openai.chat','{"model":"gpt-4o-mini","expires_in":400}'::jsonb,'{}'::jsonb,'denied','TTL escalation: child requested longer lifetime than parent',3,now()-interval '10 minutes');

    -- === AGENT INCIDENTS ===
    INSERT INTO agent_incidents (org_id,chain_id,agent_id,incident_type,severity,details,resolved,created_at) VALUES
      (v_org_id,v_chain1,v_ag3,'capability_escalation','high','{"attempted":"stripe.charge","reason":"not in allowed_tools"}'::jsonb,true,now()-interval '85 minutes'),
      (v_org_id,v_chain2,v_ag3,'ttl_escalation','high','{"requested_ttl":400,"parent_ttl":600,"decision":"rejected"}'::jsonb,false,now()-interval '10 minutes');

    -- === TELEMETRY (network sightings) ===
    FOR i IN 1..20 LOOP
      INSERT INTO ai_telemetry_events (org_id,ingestion_source_id,domain,event_type,user_hint,occurred_at,matched_policy_status,metadata_json,agent_id,risk_score,action_taken)
      VALUES (
        v_org_id, v_ing,
        (ARRAY['chat.openai.com','claude.ai','gemini.google.com','perplexity.ai','midjourney.com','deepseek.com','ollama.com'])[1+floor(random()*7)],
        'dns_query',
        (ARRAY['ivan.petrov@demo.com','anna.smirnova@demo.com','maria.kim@demo.com','dmitry.orlov@demo.com','olga.petrova@demo.com'])[1+floor(random()*5)],
        now() - (random()*interval '7 days'),
        (ARRAY['allow','allow','unknown','block'])[1+floor(random()*4)],
        '{"source":"sniffer","protocol":"dns"}'::jsonb,
        null,
        random()*10,
        (ARRAY['logged','logged','alerted','blocked'])[1+floor(random()*4)]
      );
    END LOOP;

    -- === AUDIT LOGS ===
    -- Not seeded: audit records are hash-chained and can only be written by
    -- the application (AuditService.log). Using the demo creates them.

    RAISE NOTICE 'Demo data seeded successfully';
END $$;
