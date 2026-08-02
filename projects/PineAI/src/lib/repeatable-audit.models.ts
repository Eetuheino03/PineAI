import {ReconScan} from './models';

export type MeasurementPointStatus = 'active' | 'archived';
export type AuditRunStatus = 'draft' | 'in_progress' | 'completed' | 'cancelled';
export type AuditMeasurementStatus = 'pending' | 'resolved' | 'completed' | 'failed';

export interface MeasurementPoint {
    measurement_point_id: string;
    assessment_id: string;
    location_label: string;
    physical_notes?: string;
    operator_instructions?: string;
    status: MeasurementPointStatus;
    revision: number;
    created_at?: string;
    updated_at?: string;
    archived_at?: string | null;
}

export interface AuditRunAssignmentRequest {
    measurement_point_id: string;
    measurement_profile_id: string;
    measurement_profile_version_id: string;
    baseline_version_id: string;
}

export interface AuditRunAssignment extends AuditRunAssignmentRequest {
    measurement_id?: string;
    measurement_point_revision?: number;
    measurement_point_digest?: string;
    measurement_profile_revision?: number;
    measurement_profile_digest?: string;
    baseline_digest?: string;
    [key: string]: any;
}

export interface AuditMeasurement {
    measurement_id: string;
    measurement_point_id: string;
    status: AuditMeasurementStatus;
    revision: number;
    failed_stage?: 'resolution' | 'comparison';
    error_code?: string;
    error_message?: string;
    retry_target?: 'pending' | 'resolved';
    snapshot_id?: string;
    snapshot_digest?: string;
    comparison_id?: string;
    comparison_digest?: string;
    occurrence_set_id?: string;
    evidence_ids?: string[];
    assignment?: AuditRunAssignment;
    pinned_provenance?: AuditRunAssignment;
    [key: string]: any;
}

export interface AuditRun {
    audit_run_id: string;
    assessment_id: string;
    name: string;
    description?: string;
    status: AuditRunStatus;
    revision: number;
    assurance_profile_version_id: string;
    assurance_profile_digest?: string;
    assignments?: AuditRunAssignment[];
    measurements?: AuditMeasurement[];
    created_at?: string;
    started_at?: string | null;
    completed_at?: string | null;
    cancelled_at?: string | null;
    [key: string]: any;
}

export interface AuditWorkflowState {
    current_measurement_id?: string | null;
    next_measurement_id?: string | null;
    next_action?: string | null;
}

export interface AssessmentCapacity {
    measurement_point_active_limit?: number;
    measurement_point_active_used?: number;
    measurement_point_total_limit?: number;
    measurement_point_total_used?: number;
    audit_run_limit?: number;
    audit_run_used?: number;
    audit_measurement_limit?: number;
    snapshot_limit?: number;
    snapshot_used?: number;
    comparison_limit?: number;
    comparison_used?: number;
    event_limit?: number;
    event_used?: number;
    [key: string]: number | boolean | string;
}

export interface ResourceTelemetry {
    status?: 'ready' | 'degraded' | 'blocked';
    process_rss_bytes?: number;
    process_peak_rss_bytes?: number;
    memory_available_bytes?: number;
    disk_free_bytes?: number;
    assessment_bytes?: number;
    load_average?: number[] | {
        one_minute?: number;
        five_minutes?: number;
        fifteen_minutes?: number;
    };
    scan_processing_busy?: boolean;
    transaction_recovery_state?: string;
    resource_guard?: {
        allowed?: boolean;
        reasons?: string[];
        [key: string]: any;
    };
    memory?: {
        process_rss_bytes?: number;
        process_peak_rss_bytes?: number;
        mem_available_bytes?: number;
        mem_total_bytes?: number;
    };
    storage?: {
        status?: string;
        free_bytes?: number;
        total_bytes?: number;
    };
    artifacts?: {
        assessment_count?: number;
        file_count?: number;
        total_bytes?: number;
        truncated?: boolean;
    };
    scan_processing?: {status?: string};
    blocking_codes?: string[];
    warnings?: string[];
    [key: string]: any;
}

export interface RepeatableAuditCapabilities {
    schema_version?: string;
    actions?: {[key: string]: string};
    limits?: {[key: string]: number};
    statuses?: {[key: string]: string[]};
    privacy_profiles?: string[];
    [key: string]: any;
}

export interface AuditRunDetail {
    audit_run: AuditRun;
    measurements: AuditMeasurement[];
    workflow: AuditWorkflowState;
    capacity: AssessmentCapacity | null;
}

export interface AuditReportResult {
    report_id?: string;
    fact_digest?: string;
    content_sha256?: string;
    filename?: string;
    format?: 'json' | 'html';
    content: string | any;
    [key: string]: any;
}

export interface SessionReconSelection {
    scan: ReconScan;
    data: any;
}

export interface RepeatableAuditFrontendError {
    code: string;
    message: string;
}
