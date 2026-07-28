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
    radio_profile_match?: boolean | null;
    channel_coverage_ratio?: number | null;
    baseline_ap_detection_ratio?: number | null;
    matched_ap_signal_stability?: number | null;
    baseline?: any;
    current?: any;
}

