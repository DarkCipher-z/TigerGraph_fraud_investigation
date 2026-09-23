-- ========================================================
-- Supabase / PostgreSQL Schema with pgvector
-- Fraud Investigation Management & Policy Knowledge Store
-- ========================================================

-- Enable vector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- 1. Policy Documents & Embeddings for GraphRAG
CREATE TABLE IF NOT EXISTS policy_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    full_text TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES policy_documents(id) ON DELETE CASCADE,
    chunk_index INT NOT NULL,
    section_title TEXT NOT NULL,
    content TEXT NOT NULL,
    mandatory_sar BOOLEAN DEFAULT FALSE,
    step_up_required BOOLEAN DEFAULT FALSE,
    embedding vector(768), -- text-embedding-004 dimension
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Vector similarity search RPC function for policy matching
CREATE OR REPLACE FUNCTION match_policy_chunks(
    query_embedding vector(768),
    match_threshold float DEFAULT 0.5,
    match_count int DEFAULT 5
)
RETURNS TABLE (
    id UUID,
    policy_id UUID,
    section_title TEXT,
    content TEXT,
    mandatory_sar BOOLEAN,
    similarity float
)
LANGUAGE sql STABLE
AS $$
    SELECT
        pc.id,
        pc.policy_id,
        pc.section_title,
        pc.content,
        pc.mandatory_sar,
        1 - (pc.embedding <=> query_embedding) AS similarity
    FROM policy_chunks pc
    WHERE 1 - (pc.embedding <=> query_embedding) > match_threshold
    ORDER BY pc.embedding <=> query_embedding
    LIMIT match_count;
$$;

-- 2. Case Metadata & Real-time State Store
CREATE TABLE IF NOT EXISTS case_metadata (
    case_id TEXT PRIMARY KEY,
    trigger_type TEXT NOT NULL,
    primary_card_id TEXT NOT NULL,
    primary_account_id TEXT,
    risk_score NUMERIC(5, 2) NOT NULL,
    confidence NUMERIC(4, 3) NOT NULL,
    uncertainty NUMERIC(4, 3) NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- 'open', 'under_review', 'resolved_fraud', 'resolved_cleared'
    investigation_round INT DEFAULT 1,
    assigned_analyst TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- 3. Case Decision Events Timeline
CREATE TABLE IF NOT EXISTS case_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id TEXT REFERENCES case_metadata(case_id) ON DELETE CASCADE,
    step_number INT NOT NULL,
    step_name TEXT NOT NULL,
    event_payload JSONB NOT NULL,
    llm_provider TEXT,
    latency_ms INT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 4. Case Summary Vectors for Case Memory
CREATE TABLE IF NOT EXISTS case_summary_vectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id TEXT REFERENCES case_metadata(case_id) ON DELETE CASCADE,
    summary_text TEXT NOT NULL,
    outcome TEXT NOT NULL, -- 'confirmed_fraud', 'cleared_benign'
    typology TEXT NOT NULL,
    embedding vector(768),
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Vector match for similar prior cases
CREATE OR REPLACE FUNCTION match_prior_cases(
    query_embedding vector(768),
    match_threshold float DEFAULT 0.6,
    match_count int DEFAULT 3
)
RETURNS TABLE (
    case_id TEXT,
    summary_text TEXT,
    outcome TEXT,
    typology TEXT,
    similarity float
)
LANGUAGE sql STABLE
AS $$
    SELECT
        csv.case_id,
        csv.summary_text,
        csv.outcome,
        csv.typology,
        1 - (csv.embedding <=> query_embedding) AS similarity
    FROM case_summary_vectors csv
    WHERE 1 - (csv.embedding <=> query_embedding) > match_threshold
    ORDER BY csv.embedding <=> query_embedding
    LIMIT match_count;
$$;

-- 5. Action Audit & Human-in-the-Loop Governance
CREATE TABLE IF NOT EXISTS action_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id TEXT REFERENCES case_metadata(case_id) ON DELETE CASCADE,
    stage TEXT NOT NULL, -- 'pre_evidence', 'post_evidence'
    action_type TEXT NOT NULL, -- 'block_account', 'step_up_mfa', 'file_sar', 'notify_customer', etc.
    parameters JSONB DEFAULT '{}'::jsonb,
    is_critical BOOLEAN DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'proposed', -- 'proposed', 'approved', 'rejected', 'executed'
    proposed_by TEXT NOT NULL DEFAULT 'agent_orchestrator',
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    execution_result JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 6. Suspicious Activity Reports (SAR) Store
CREATE TABLE IF NOT EXISTS sar_filings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id TEXT REFERENCES case_metadata(case_id) ON DELETE CASCADE,
    sar_reference_id TEXT NOT NULL UNIQUE,
    subject_details JSONB NOT NULL,
    suspicious_amount NUMERIC(12, 2) NOT NULL,
    typology TEXT NOT NULL,
    narrative TEXT NOT NULL,
    status TEXT DEFAULT 'draft', -- 'draft', 'pending_approval', 'filed_to_fincen'
    filed_by TEXT,
    filed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- ========================================================
-- Row Level Security (RLS) Policies
-- ========================================================
ALTER TABLE case_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE sar_filings ENABLE ROW LEVEL SECURITY;

-- Allow authenticated read/write
CREATE POLICY "Allow read for authenticated users" ON case_metadata FOR SELECT USING (true);
CREATE POLICY "Allow insert/update for service role" ON case_metadata FOR ALL USING (true);

CREATE POLICY "Allow read audit log" ON action_audit FOR SELECT USING (true);
CREATE POLICY "Allow insert audit log" ON action_audit FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow update approval only for authenticated" ON action_audit FOR UPDATE USING (true);

CREATE POLICY "Allow read sar filings" ON sar_filings FOR SELECT USING (true);
CREATE POLICY "Allow write sar filings" ON sar_filings FOR ALL USING (true);
