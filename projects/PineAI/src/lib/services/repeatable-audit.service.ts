import {Injectable} from '@angular/core';
import {ApiService} from './api.service';
import {
    AssessmentCapacity,
    AuditMeasurement,
    AuditReportResult,
    AuditRun,
    AuditRunAssignmentRequest,
    AuditRunDetail,
    AuditWorkflowState,
    MeasurementPoint,
    RepeatableAuditCapabilities,
    RepeatableAuditFrontendError,
    ResourceTelemetry
} from '../repeatable-audit.models';

@Injectable({providedIn: 'root'})
export class RepeatableAuditService {
    capabilities: RepeatableAuditCapabilities = null;
    telemetry: ResourceTelemetry = null;
    measurementPoints: MeasurementPoint[] = [];
    auditRuns: AuditRun[] = [];
    selectedRun: AuditRun = null;
    measurements: AuditMeasurement[] = [];
    workflow: AuditWorkflowState = {};
    capacity: AssessmentCapacity = null;
    busyAction = '';
    error: RepeatableAuditFrontendError = null;

    constructor(private api: ApiService) {}

    clearAssessment(): void {
        this.measurementPoints = [];
        this.auditRuns = [];
        this.selectedRun = null;
        this.measurements = [];
        this.workflow = {};
        this.capacity = null;
        this.telemetry = null;
        this.error = null;
    }

    async initializeAssessment(assessmentId: string): Promise<void> {
        this.clearAssessment();
        await this.run('initialize', async () => {
            await this.loadCapabilities().catch(() => {
                this.capabilities = {};
            });
            const required = Promise.all([
                this.refreshMeasurementPoints(assessmentId),
                this.refreshAuditRuns(assessmentId)
            ]);
            await Promise.all([
                required,
                this.refreshTelemetry(assessmentId).catch(() => {
                    this.telemetry = {
                        status: 'degraded',
                        resource_guard: {
                            allowed: false,
                            reasons: ['telemetry_unavailable']
                        }
                    };
                })
            ]);
        });
    }

    async loadCapabilities(): Promise<RepeatableAuditCapabilities> {
        this.capabilities = await this.module<RepeatableAuditCapabilities>(
            'repeatable_audit_capabilities'
        );
        return this.capabilities;
    }

    async refreshTelemetry(assessmentId?: string): Promise<ResourceTelemetry> {
        const value = await this.module<ResourceTelemetry>(
            'resource_telemetry',
            assessmentId ? {assessment_id: assessmentId} : {}
        );
        this.telemetry = this.normalizeTelemetry(value);
        return this.telemetry;
    }

    async refreshMeasurementPoints(
        assessmentId: string,
        includeArchived: boolean = false
    ): Promise<MeasurementPoint[]> {
        const result: any = await this.module<any>('list_measurement_points', {
            assessment_id: assessmentId,
            include_archived: includeArchived,
            limit: 100,
            offset: 0
        });
        this.measurementPoints = this.arrayFrom(
            result,
            'measurement_points'
        );
        this.captureCapacity(result);
        return this.measurementPoints;
    }

    async getMeasurementPoint(
        assessmentId: string,
        measurementPointId: string
    ): Promise<MeasurementPoint> {
        const result: any = await this.module<any>('get_measurement_point', {
            assessment_id: assessmentId,
            measurement_point_id: measurementPointId
        });
        return this.objectFrom<MeasurementPoint>(result, 'measurement_point');
    }

    async createMeasurementPoint(
        assessmentId: string,
        assessmentRevision: number,
        point: {
            location_label: string;
            physical_notes?: string;
            operator_instructions?: string;
        }
    ): Promise<any> {
        return this.mutate('create_point', 'create_measurement_point', {
            assessment_id: assessmentId,
            expected_assessment_revision: assessmentRevision,
            measurement_point: point
        }, async (result) => {
            await this.refreshMeasurementPoints(assessmentId);
            this.captureCapacity(result);
        });
    }

    async updateMeasurementPoint(
        assessmentId: string,
        assessmentRevision: number,
        point: MeasurementPoint,
        changes: any
    ): Promise<any> {
        return this.mutate('update_point', 'update_measurement_point', {
            assessment_id: assessmentId,
            measurement_point_id: point.measurement_point_id,
            expected_assessment_revision: assessmentRevision,
            expected_measurement_point_revision: point.revision,
            changes
        }, async (result) => {
            await this.refreshMeasurementPoints(assessmentId);
            this.captureCapacity(result);
        });
    }

    async archiveMeasurementPoint(
        assessmentId: string,
        assessmentRevision: number,
        point: MeasurementPoint
    ): Promise<any> {
        return this.mutate('archive_point', 'archive_measurement_point', {
            assessment_id: assessmentId,
            measurement_point_id: point.measurement_point_id,
            expected_assessment_revision: assessmentRevision,
            expected_measurement_point_revision: point.revision
        }, async (result) => {
            await this.refreshMeasurementPoints(assessmentId);
            this.captureCapacity(result);
        });
    }

    async refreshAuditRuns(assessmentId: string): Promise<AuditRun[]> {
        const result: any = await this.module<any>('list_audit_runs', {
            assessment_id: assessmentId,
            limit: 100,
            offset: 0
        });
        this.auditRuns = this.arrayFrom<any>(result, 'audit_runs')
            .map((entry: any) => entry && entry.audit_run
                ? entry.audit_run
                : entry)
            .filter((run: any) => !!run && !!run.audit_run_id);
        this.captureCapacity(result);
        if (this.selectedRun) {
            this.selectedRun = this.auditRuns.find(
                (run) => run.audit_run_id === this.selectedRun.audit_run_id
            ) || this.selectedRun;
        }
        return this.auditRuns;
    }

    async createAuditRun(
        assessmentId: string,
        assessmentRevision: number,
        value: {
            name: string;
            description?: string;
            assurance_profile_version_id: string;
            assignments: AuditRunAssignmentRequest[];
        }
    ): Promise<any> {
        return this.mutate('create_run', 'create_audit_run', {
            assessment_id: assessmentId,
            expected_assessment_revision: assessmentRevision,
            audit_run: value
        }, async (result) => {
            await this.refreshAuditRuns(assessmentId);
            const run = this.objectFrom<AuditRun>(result, 'audit_run');
            if (run && run.audit_run_id) {
                await this.fetchRunDetail(assessmentId, run.audit_run_id);
            }
        });
    }

    async selectAuditRun(
        assessmentId: string,
        auditRunId: string
    ): Promise<AuditRunDetail> {
        return this.run('load_run', async () => {
            return this.fetchRunDetail(assessmentId, auditRunId);
        });
    }

    async startAuditRun(
        assessmentId: string,
        assessmentRevision: number
    ): Promise<any> {
        return this.runMutation('start_run', 'start_audit_run', {
            assessment_id: assessmentId,
            audit_run_id: this.requireRun().audit_run_id,
            expected_assessment_revision: assessmentRevision,
            expected_audit_run_revision: this.requireRun().revision
        });
    }

    async cancelAuditRun(
        assessmentId: string,
        assessmentRevision: number
    ): Promise<any> {
        return this.runMutation('cancel_run', 'cancel_audit_run', {
            assessment_id: assessmentId,
            audit_run_id: this.requireRun().audit_run_id,
            expected_assessment_revision: assessmentRevision,
            expected_audit_run_revision: this.requireRun().revision
        });
    }

    async completeAuditRun(
        assessmentId: string,
        assessmentRevision: number
    ): Promise<any> {
        return this.runMutation('complete_run', 'complete_audit_run', {
            assessment_id: assessmentId,
            audit_run_id: this.requireRun().audit_run_id,
            expected_assessment_revision: assessmentRevision,
            expected_audit_run_revision: this.requireRun().revision
        });
    }

    async resolveAuditMeasurement(
        assessmentId: string,
        assessmentRevision: number,
        measurement: AuditMeasurement,
        scan: any,
        scanMetadata: any
    ): Promise<any> {
        return this.runMutation('resolve_measurement', 'resolve_audit_measurement', {
            assessment_id: assessmentId,
            audit_run_id: this.requireRun().audit_run_id,
            measurement_id: measurement.measurement_id,
            expected_assessment_revision: assessmentRevision,
            expected_audit_run_revision: this.requireRun().revision,
            expected_measurement_revision: measurement.revision,
            scan,
            scan_metadata: scanMetadata
        });
    }

    async saveAuditMeasurementComparison(
        assessmentId: string,
        assessmentRevision: number,
        measurement: AuditMeasurement
    ): Promise<any> {
        return this.runMutation(
            'compare_measurement',
            'save_audit_measurement_comparison',
            {
                assessment_id: assessmentId,
                audit_run_id: this.requireRun().audit_run_id,
                measurement_id: measurement.measurement_id,
                expected_assessment_revision: assessmentRevision,
                expected_audit_run_revision: this.requireRun().revision,
                expected_measurement_revision: measurement.revision
            }
        );
    }

    async retryAuditMeasurement(
        assessmentId: string,
        assessmentRevision: number,
        measurement: AuditMeasurement
    ): Promise<any> {
        return this.runMutation('retry_measurement', 'retry_audit_measurement', {
            assessment_id: assessmentId,
            audit_run_id: this.requireRun().audit_run_id,
            measurement_id: measurement.measurement_id,
            expected_assessment_revision: assessmentRevision,
            expected_audit_run_revision: this.requireRun().revision,
            expected_measurement_revision: measurement.revision
        });
    }

    async generateAuditRunReport(
        assessmentId: string,
        format: 'json' | 'html',
        privacyProfile: 'local_full' | 'share_safe'
    ): Promise<AuditReportResult> {
        return this.run('generate_report', async () => {
            return this.module<AuditReportResult>('generate_audit_run_report', {
                assessment_id: assessmentId,
                audit_run_id: this.requireRun().audit_run_id,
                format,
                privacy_profile: privacyProfile
            });
        });
    }

    downloadReport(result: AuditReportResult): void {
        if (!result) {
            return;
        }
        const format = result.format || (
            result.filename && result.filename.toLowerCase().endsWith('.html')
                ? 'html' : 'json'
        );
        const filename = result.filename ||
            `pineassure-audit-run.${format === 'html' ? 'html' : 'json'}`;
        const content = typeof result.content === 'string'
            ? result.content : JSON.stringify(result.content, null, 2);
        const blob = new Blob([content], {
            type: format === 'html'
                ? 'text/html;charset=utf-8'
                : 'application/json;charset=utf-8'
        });
        const url = window.URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.style.display = 'none';
        anchor.href = url;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        window.URL.revokeObjectURL(url);
        anchor.remove();
    }

    activeMeasurement(): AuditMeasurement | null {
        const workflowValue = this.workflow || {};
        const hasAuthoritativeIds = Object.prototype.hasOwnProperty.call(
            workflowValue, 'current_measurement_id'
        ) || Object.prototype.hasOwnProperty.call(
            workflowValue, 'next_measurement_id'
        );
        const selectedId = workflowValue.current_measurement_id ||
            workflowValue.next_measurement_id;
        if (hasAuthoritativeIds) {
            if (!selectedId) {
                return null;
            }
            return this.measurements.find(
                (value) => value.measurement_id === selectedId
            ) || null;
        }
        return this.measurements.find(
            (value) => value.status !== 'completed'
        ) || null;
    }

    pointForMeasurement(measurement: AuditMeasurement): MeasurementPoint {
        return measurement ? this.measurementPoints.find(
            (point) => point.measurement_point_id ===
                measurement.measurement_point_id
        ) || null : null;
    }

    private async runMutation(
        busyAction: string,
        action: string,
        payload: any
    ): Promise<any> {
        return this.mutate(busyAction, action, payload, async (result) => {
            const current = this.selectedRun;
            const returned = result && result.audit_run;
            const assessmentId = returned && returned.assessment_id ||
                current && current.assessment_id;
            const auditRunId = returned && returned.audit_run_id ||
                current && current.audit_run_id;
            if (assessmentId && auditRunId) {
                await this.fetchRunDetail(assessmentId, auditRunId);
                await this.refreshAuditRuns(assessmentId);
            }
        });
    }

    private async fetchRunDetail(
        assessmentId: string,
        auditRunId: string
    ): Promise<AuditRunDetail> {
        const result: any = await this.module<any>('get_audit_run', {
            assessment_id: assessmentId,
            audit_run_id: auditRunId
        });
        return this.applyRunDetail(result);
    }

    private async mutate(
        busyAction: string,
        action: string,
        payload: any,
        after: (result: any) => Promise<void>
    ): Promise<any> {
        return this.run(busyAction, async () => {
            const result = await this.module<any>(action, payload);
            this.captureCapacity(result);
            await after(result);
            return result;
        });
    }

    private applyRunDetail(result: any): AuditRunDetail {
        const run = this.objectFrom<AuditRun>(result, 'audit_run');
        if (!run || !run.audit_run_id) {
            throw {
                code: 'invalid_audit_run_response',
                message: 'The backend did not return an AuditRun.'
            };
        }
        const measurements = Array.isArray(result && result.measurements)
            ? result.measurements
            : Array.isArray(run.measurements) ? run.measurements : [];
        const workflowSource = result && result.workflow
            ? result.workflow : result || {};
        const workflow: AuditWorkflowState = {
            current_measurement_id: this.workflowId(
                workflowSource.current_measurement_id
            ),
            next_measurement_id: this.workflowId(
                workflowSource.next_measurement_id
            ),
            next_action: typeof workflowSource.next_action === 'string'
                ? workflowSource.next_action : null
        };
        this.selectedRun = run;
        this.measurements = measurements;
        this.workflow = workflow;
        this.captureCapacity(result);
        return {
            audit_run: run,
            measurements,
            workflow,
            capacity: this.capacity
        };
    }

    private workflowId(value: any): string | null {
        return typeof value === 'string' && value ? value : null;
    }

    private captureCapacity(result: any): void {
        const value = result && (
            result.assessment_capacity || result.capacity
        );
        if (value) {
            this.capacity = value;
        }
    }

    private normalizeTelemetry(value: ResourceTelemetry): ResourceTelemetry {
        const result: ResourceTelemetry = Object.assign({}, value || {});
        const memory = result.memory || {};
        const storage = result.storage || {};
        const processing = result.scan_processing || {};
        if (result.process_rss_bytes === undefined) {
            result.process_rss_bytes = memory.process_rss_bytes;
        }
        if (result.process_peak_rss_bytes === undefined) {
            result.process_peak_rss_bytes = memory.process_peak_rss_bytes;
        }
        if (result.memory_available_bytes === undefined) {
            result.memory_available_bytes = memory.mem_available_bytes;
        }
        if (result.disk_free_bytes === undefined) {
            result.disk_free_bytes = storage.free_bytes;
        }
        if (result.assessment_bytes === undefined && result.artifacts) {
            result.assessment_bytes = result.artifacts.total_bytes;
        }
        if (result.scan_processing_busy === undefined) {
            result.scan_processing_busy = processing.status === 'busy';
        }
        return result;
    }

    private requireRun(): AuditRun {
        if (!this.selectedRun) {
            throw {
                code: 'audit_run_required',
                message: 'Select an AuditRun first.'
            };
        }
        return this.selectedRun;
    }

    private objectFrom<T>(result: any, field: string): T {
        return result && result[field] ? result[field] : result as T;
    }

    private arrayFrom<T>(result: any, field: string): T[] {
        if (Array.isArray(result)) {
            return result;
        }
        return result && Array.isArray(result[field]) ? result[field] : [];
    }

    private actionName(fallback: string): string {
        const actions = this.capabilities && this.capabilities.actions;
        return actions && typeof actions[fallback] === 'string'
            ? actions[fallback] : fallback;
    }

    private module<T>(action: string, values: any = {}): Promise<T> {
        return this.api.moduleRequest<T>(Object.assign({
            module: 'PineAI',
            action: this.actionName(action)
        }, values));
    }

    private async run<T>(action: string, operation: () => Promise<T>): Promise<T> {
        if (this.busyAction) {
            throw {
                code: 'frontend_busy',
                message: `Wait for ${this.busyAction} to finish.`
            };
        }
        this.busyAction = action;
        this.error = null;
        try {
            return await operation();
        } catch (error) {
            this.error = this.normalizeError(error);
            throw error;
        } finally {
            this.busyAction = '';
        }
    }

    normalizeError(error: any): RepeatableAuditFrontendError {
        const value = error && error.error ? error.error : error;
        if (value && typeof value.code === 'string') {
            return {
                code: value.code,
                message: value.message || value.safe_message || value.code
            };
        }
        return {
            code: 'request_failed',
            message: value && value.message
                ? value.message : 'The request failed.'
        };
    }
}
