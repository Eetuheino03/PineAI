export type ResourceLoadState =
    'not_loaded' | 'loading' | 'loaded' | 'failed';

export interface PineAISettings {
    schema_version?: string;
    model?: string;
    language: 'en' | 'fi';
    share_ssids: boolean;
    api_key_configured: boolean;
    api_key_source?: 'none' | 'file' | 'environment';
}

export interface ReconStatus {
    captureRunning: boolean;
    scanRunning: boolean;
    continuous?: boolean;
    scanPercent?: number;
    scanID?: number;
}

export interface ReconScan {
    scan_id: number | string;
    date?: string;
    scan_time?: number;
    band?: string;
    [key: string]: any;
}

export interface Assessment {
    assessment_id: string;
    name: string;
    location?: string;
    notes?: string;
    status?: 'active' | 'archived';
    revision: number;
    active_baseline_version?: string;
    active_baseline_version_id?: string;
    active_baseline_id?: string;
    created_at?: string;
    updated_at?: string;
    events?: any[];
    [key: string]: any;
}

export interface BaselineVersion {
    baseline_version_id?: string;
    baseline_id?: string;
    version?: number;
    status?: string;
    active?: boolean;
    is_active?: boolean;
    created_at?: string;
    scan_summary?: any;
    [key: string]: any;
}

export interface Finding {
    finding_id: string;
    rule_id?: string;
    title?: string;
    summary?: string;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence?: number;
    status: 'open' | 'acknowledged' | 'false_positive' | 'resolved';
    target_id?: string;
    evidence_ids?: string[];
    first_seen?: string;
    last_seen?: string;
    occurrence_count?: number;
    [key: string]: any;
}

export interface ActivityEntry {
    time: string;
    level: 'info' | 'success' | 'warning' | 'error';
    title: string;
    detail: string;
}

export interface FrontendError {
    code: string;
    message: string;
}

export interface PanelErrorMap {
    [panel: string]: FrontendError;
}

export interface MeasurementContext {
    location_id?: string | null;
    measurement_point_id?: string | null;
    scan_profile_id?: string | null;
    radio_profile_id?: string | null;
    interface?: string | null;
    declared_channels?: number[] | null;
    declared_bands?: string[] | null;
    scan_time?: number | null;
    five_ghz_operator_confirmed?: boolean | null;
    measurement_profile_id?: string | null;
    measurement_profile_version_id?: string | null;
    measurement_profile_revision?: number | null;
    measurement_profile_digest?: string | null;
}

export interface QualityFactors {
    duration_score?: number | null;
    channel_coverage_score?: number | null;
    baseline_detection_score?: number | null;
    radio_profile_score?: number | null;
}

export interface ComparabilityEvaluation {
    status: 'comparable' | 'partially_comparable' | 'not_comparable';
    positive_findings_allowed: boolean;
    absence_findings_allowed: boolean;
    lifecycle_updates_allowed: boolean;
    reasons: string[];
    comparison_quality_score?: number | null;
    quality_model_version?: string | null;
    quality_factors?: QualityFactors | null;
    location_match?: boolean | null;
    measurement_point_match?: boolean | null;
    scan_profile_match?: boolean | null;
    radio_profile_match?: boolean | null;
    interface_match?: boolean | null;
    channel_coverage_ratio?: number | null;
    eligible_baseline_ap_count?: number;
    reobserved_baseline_ap_count?: number;
    baseline_ap_detection_ratio?: number | null;
    matched_ap_signal_stability?: {
        matched_ap_count: number;
        median_absolute_delta_db: number | null;
    } | null;
    baseline?: any;
    current?: any;
}

export type CapabilityLevel = 'ready' | 'degraded' | 'blocked';

export interface CapabilitySummary {
    level: CapabilityLevel;
    title: string;
    detail: string;
    unavailable: string[];
}

export interface MeasurementProfile {
    measurement_profile_id: string;
    profile_id?: string;
    version_id?: string;
    revision: number;
    name: string;
    description?: string;
    status?: 'active' | 'archived';
    is_default?: boolean;
    context: MeasurementContext;
    created_at?: string;
    updated_at?: string;
    digest?: string;
}

export type WorkflowMode = 'baseline' | 'comparison';

export type WorkflowStepKey =
    'assessment' |
    'measurement_profile' |
    'recon_scans' |
    'baseline_comparison' |
    'inventory_policy' |
    'analysis_evidence' |
    'report';

export type WorkflowStepState =
    'blocked' | 'ready' | 'active' | 'complete' | 'error';

export interface WorkflowScanSelection {
    scan_id: string;
    scan: ReconScan;
    loaded: boolean;
    error?: FrontendError;
}

export interface WorkflowState {
    mode: WorkflowMode;
    current_step: WorkflowStepKey;
    assessment_id: string;
    assessment_revision: number | null;
    measurement_profile_id: string;
    measurement_profile_revision: number | null;
    selected_scans: WorkflowScanSelection[];
    consensus_preview_digest: string;
    baseline_version_id: string;
    assurance_profile_revision: number | null;
    assurance_profile_confirmed: boolean;
    comparison_preview_ready: boolean;
    comparison_id: string;
    analysis_saved: boolean;
    report_scope_digest: string;
    busy_action: string;
    step_states: {[key: string]: WorkflowStepState};
}

export interface ConsensusConflict {
    subject_id?: string;
    field?: string;
    values?: any[];
    reason?: string;
}

export interface ConsensusBaselinePreview {
    schema_version?: string;
    preview_digest?: string;
    consensus_digest?: string;
    source_scan_count?: number;
    presence_ratio?: number;
    included_access_points?: any[];
    excluded_access_points?: any[];
    conflicts?: ConsensusConflict[];
    quality?: any;
    baseline_summary?: any;
    [key: string]: any;
}

export interface InventoryItem {
    inventory_id?: string;
    kind: 'ap' | 'network';
    subject_id: string;
    label?: string;
    criticality?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    expected_presence?: boolean;
    allowed_encryption_codes?: Array<number | string>;
    allowed_channels?: number[];
    wps_allowed?: boolean;
    allowed_vendors?: string[];
    notes?: string;
    status?: 'active' | 'archived';
}

export interface AssurancePolicy {
    require_expected_assets?: boolean;
    forbid_wps?: boolean;
    require_encryption_consistency?: boolean;
    allowed_channels?: number[];
    allowed_encryption_codes?: Array<number | string>;
    allowed_vendors?: string[];
    [key: string]: any;
}

export interface AssuranceProfile {
    assurance_profile_id?: string;
    profile_id?: string;
    revision?: number;
    version?: number;
    status?: 'draft' | 'active' | 'archived';
    active?: boolean;
    name?: string;
    inventory_items: InventoryItem[];
    policy: AssurancePolicy;
    digest?: string;
    created_at?: string;
    updated_at?: string;
}

export interface InventoryImportPreview {
    rows: InventoryItem[];
    valid?: boolean;
    row_count?: number;
    errors: Array<{
        row?: number;
        code: string;
        message: string;
    }>;
    warnings?: string[];
    valid_count?: number;
    invalid_count?: number;
    preview_digest?: string;
}

export interface EvidenceValue {
    evidence_id?: string;
    snapshot_id?: string;
    subject_id?: string;
    observed_at?: string;
    value: any;
}

export interface EvidencePair {
    field: string;
    change_type?: string;
    before: EvidenceValue | null;
    after: EvidenceValue | null;
    interpretation_code?: string;
}

export interface EvidenceBundle {
    bundle_id?: string;
    digest?: string;
    finding_id: string;
    comparison_id?: string;
    comparability?: ComparabilityEvaluation;
    pairs: EvidencePair[];
    [key: string]: any;
}

export type FindingTaxonomy =
    'observed_change' | 'deviation' | 'security_finding';

export interface ResultTaxonomy {
    observed_changes: any[];
    deviations: any[];
    security_findings: any[];
}

export type ReportFindingMode = 'comparison' | 'active' | 'all';

export interface ReportScope {
    type: 'comparison' | 'assessment_current' | 'assessment_history';
    comparison_id?: string;
    finding_mode?: ReportFindingMode;
    statuses?: string[];
    severities?: string[];
    rule_ids?: string[];
    subject_ids?: string[];
    include_evidence?: boolean;
    include_inventory_policy?: boolean;
    include_ai?: boolean;
}

export interface ReportScopeManifest {
    comparison_ids?: string[];
    finding_ids?: string[];
    finding_count?: number;
    evidence_count?: number;
    inventory_revision?: number | null;
    policy_revision?: number | null;
    warnings?: string[];
    [key: string]: any;
}

export interface ReportScopePreview {
    scope_digest: string;
    manifest: ReportScopeManifest;
    warnings?: string[];
    [key: string]: any;
}

