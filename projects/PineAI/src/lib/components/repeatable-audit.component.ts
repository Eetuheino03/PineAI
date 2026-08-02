import {Component, OnInit} from '@angular/core';
import {Assessment, BaselineVersion, MeasurementProfile, ReconScan} from '../models';
import {
    AuditMeasurement,
    AuditReportResult,
    AuditRun,
    AuditRunAssignmentRequest,
    MeasurementPoint
} from '../repeatable-audit.models';
import {PineAIService} from '../services/PineAI.service';
import {RepeatableAuditService} from '../services/repeatable-audit.service';
import {
    RepeatableAuditWorkflowFacade
} from '../services/repeatable-audit-workflow.facade';

@Component({
    selector: 'lib-pineai-repeatable-audit',
    templateUrl: './repeatable-audit.component.html',
    styleUrls: ['./shared.css', './repeatable-audit.component.css']
})
export class RepeatableAuditComponent implements OnInit {
    readonly savedScanProvenanceNotice =
        'MeasurementProfile settings are an operator-declared collection ' +
        'contract. Hak5 saved Recon does not independently prove that this ' +
        'scan used the pinned interface, bands, channels, duration or radio ' +
        'profile.';
    selectedAssessmentId = '';
    pointLocation = '';
    pointPhysicalNotes = '';
    pointInstructions = '';
    runName = '';
    runDescription = '';
    selectedRunId = '';
    reportFormat: 'json' | 'html' = 'html';
    privacyProfile: 'local_full' | 'share_safe' = 'local_full';
    reportResult: AuditReportResult = null;
    terminalConfirmed = false;
    editingPoint: MeasurementPoint = null;
    profileByPoint: {[pointId: string]: string} = {};
    baselineByPoint: {[pointId: string]: string} = {};

    constructor(
        public pineai: PineAIService,
        public audit: RepeatableAuditService,
        public flow: RepeatableAuditWorkflowFacade
    ) {}

    async ngOnInit(): Promise<void> {
        if (this.pineai.activeAssessment) {
            this.selectedAssessmentId =
                this.pineai.activeAssessment.assessment_id;
            await this.openAssessment(true);
        }
    }

    get assessment(): Assessment {
        return this.pineai.activeAssessment;
    }

    get run(): AuditRun {
        return this.audit.selectedRun;
    }

    get currentMeasurement(): AuditMeasurement {
        return this.audit.activeMeasurement();
    }

    get currentPoint(): MeasurementPoint {
        return this.audit.pointForMeasurement(this.currentMeasurement);
    }

    get reportFactDigest(): string {
        return this.reportResult && this.reportResult.fact_digest || '';
    }

    get assuranceProfileId(): string {
        return this.pineai.assuranceProfileId(this.pineai.assuranceProfile);
    }

    get canCreateRun(): boolean {
        return !!this.assessment && !!this.runName.trim() &&
            !!this.assuranceProfileId &&
            this.flow.selectedPointIds.length > 0 &&
            this.flow.validAssignments().length ===
                this.flow.selectedPointIds.length;
    }

    get terminalRun(): boolean {
        return !!this.run && (
            this.run.status === 'completed' || this.run.status === 'cancelled'
        );
    }

    get resourceBlocked(): boolean {
        return !!this.audit.telemetry &&
            this.audit.telemetry.status === 'blocked';
    }

    get allMeasurementsComplete(): boolean {
        return this.audit.measurements.length > 0 &&
            this.audit.measurements.every(
                (measurement) => measurement.status === 'completed'
            );
    }

    get currentProvenance(): any {
        if (!this.currentMeasurement) {
            return {};
        }
        return this.currentMeasurement.pinned_provenance ||
            this.currentMeasurement.assignment || this.currentMeasurement;
    }

    async openAssessment(resetFlow: boolean = true): Promise<void> {
        if (!this.selectedAssessmentId) {
            this.flow.setError('assessment', {
                code: 'assessment_required',
                message: 'Select an assessment.'
            });
            return;
        }
        await this.execute('assessment', async () => {
            await this.pineai.selectAssessment(this.selectedAssessmentId);
            if (resetFlow) {
                this.flow.resetForAssessment(this.selectedAssessmentId);
            }
            await Promise.all([
                this.pineai.ensureMeasurementProfilesLoaded(),
                this.pineai.ensureReconLoaded(),
                this.audit.initializeAssessment(this.selectedAssessmentId)
            ]);
            this.flow.selectedStep = 1;
        }, 'Assessment loaded. Create or select measurement points.');
    }

    async refreshAssessmentState(): Promise<void> {
        if (!this.assessment) {
            return;
        }
        await this.execute('assessment', async () => {
            await this.pineai.selectAssessment(
                this.assessment.assessment_id,
                true
            );
            await Promise.all([
                this.audit.refreshMeasurementPoints(
                    this.assessment.assessment_id
                ),
                this.audit.refreshAuditRuns(this.assessment.assessment_id),
                this.audit.refreshTelemetry(this.assessment.assessment_id)
            ]);
            if (this.selectedRunId) {
                await this.audit.selectAuditRun(
                    this.assessment.assessment_id,
                    this.selectedRunId
                );
            }
        }, 'Assessment state refreshed.');
    }

    async createPoint(): Promise<void> {
        if (!this.assessment || !this.pointLocation.trim()) {
            this.flow.setError('points', {
                code: 'invalid_measurement_point',
                message: 'A location label and assessment are required.'
            });
            return;
        }
        await this.execute('points', async () => {
            const value = {
                location_label: this.pointLocation.trim(),
                physical_notes: this.pointPhysicalNotes.trim(),
                operator_instructions: this.pointInstructions.trim()
            };
            const result = this.editingPoint
                ? await this.audit.updateMeasurementPoint(
                    this.assessment.assessment_id,
                    this.assessment.revision,
                    this.editingPoint,
                    value
                )
                : await this.audit.createMeasurementPoint(
                    this.assessment.assessment_id,
                    this.assessment.revision,
                    value
                );
            await this.syncAssessmentRevision(result);
            this.clearPointForm();
        }, this.editingPoint
            ? 'Measurement point updated.'
            : 'Measurement point created. No scan was started.');
    }

    editPoint(point: MeasurementPoint): void {
        this.editingPoint = point;
        this.pointLocation = point.location_label || '';
        this.pointPhysicalNotes = point.physical_notes || '';
        this.pointInstructions = point.operator_instructions || '';
        this.flow.clearFeedback('points');
    }

    clearPointForm(): void {
        this.editingPoint = null;
        this.pointLocation = '';
        this.pointPhysicalNotes = '';
        this.pointInstructions = '';
    }

    async archivePoint(point: MeasurementPoint): Promise<void> {
        if (!this.assessment) {
            return;
        }
        await this.execute('points', async () => {
            const result = await this.audit.archiveMeasurementPoint(
                this.assessment.assessment_id,
                this.assessment.revision,
                point
            );
            this.flow.selectPoint(point.measurement_point_id, false);
            if (this.editingPoint && this.editingPoint.measurement_point_id ===
                point.measurement_point_id) {
                this.clearPointForm();
            }
            await this.syncAssessmentRevision(result);
        }, `Measurement point "${point.location_label}" archived.`);
    }

    togglePoint(point: MeasurementPoint, selected: boolean): void {
        this.flow.selectPoint(point.measurement_point_id, selected);
        if (selected) {
            const firstProfile = this.availableProfiles[0];
            const firstBaseline = this.availableBaselines[0];
            this.profileByPoint[point.measurement_point_id] =
                firstProfile ? this.profileId(firstProfile) : '';
            this.baselineByPoint[point.measurement_point_id] =
                firstBaseline ? this.baselineId(firstBaseline) : '';
            this.updateAssignment(point.measurement_point_id);
        }
    }

    profileChanged(pointId: string, profileId: string): void {
        this.profileByPoint[pointId] = profileId;
        this.updateAssignment(pointId);
    }

    baselineChanged(pointId: string, baselineId: string): void {
        this.baselineByPoint[pointId] = baselineId;
        this.updateAssignment(pointId);
    }

    async createRun(): Promise<void> {
        if (!this.canCreateRun) {
            this.flow.setError('run', {
                code: 'audit_run_not_ready',
                message: 'Choose 1–16 points and pin a profile and baseline for each.'
            });
            return;
        }
        await this.execute('run', async () => {
            const result = await this.audit.createAuditRun(
                this.assessment.assessment_id,
                this.assessment.revision,
                {
                    name: this.runName.trim(),
                    description: this.runDescription.trim(),
                    assurance_profile_version_id: this.assuranceProfileId,
                    assignments: this.flow.validAssignments()
                }
            );
            await this.syncAssessmentRevision(result);
            if (this.audit.selectedRun) {
                this.selectedRunId = this.audit.selectedRun.audit_run_id;
            }
            this.runName = '';
            this.runDescription = '';
            this.flow.selectedStep = 3;
        }, 'Draft AuditRun created with immutable provenance pins.');
    }

    async openRun(): Promise<void> {
        if (!this.assessment || !this.selectedRunId) {
            return;
        }
        await this.execute('run', async () => {
            await this.audit.selectAuditRun(
                this.assessment.assessment_id,
                this.selectedRunId
            );
            this.terminalConfirmed = false;
            this.reportResult = null;
            this.flow.selectedStep = 3;
        }, 'AuditRun loaded from backend state.');
    }

    async startRun(): Promise<void> {
        await this.runMutation(
            'run',
            () => this.audit.startAuditRun(
                this.assessment.assessment_id,
                this.assessment.revision
            ),
            'AuditRun started. Select a saved Recon scan for the current point.'
        );
    }

    async cancelRun(): Promise<void> {
        if (!this.terminalConfirmed) {
            this.flow.setError('run', {
                code: 'confirmation_required',
                message: 'Confirm the terminal transition first.'
            });
            return;
        }
        await this.runMutation(
            'run',
            () => this.audit.cancelAuditRun(
                this.assessment.assessment_id,
                this.assessment.revision
            ),
            'AuditRun cancelled and sealed.'
        );
    }

    async completeRun(): Promise<void> {
        if (!this.terminalConfirmed) {
            this.flow.setError('run', {
                code: 'confirmation_required',
                message: 'Confirm the terminal transition first.'
            });
            return;
        }
        await this.runMutation(
            'run',
            () => this.audit.completeAuditRun(
                this.assessment.assessment_id,
                this.assessment.revision
            ),
            'AuditRun completed and sealed.'
        );
    }

    async selectSavedScan(scanId: string): Promise<void> {
        const measurement = this.currentMeasurement;
        const scan = this.pineai.scans.find(
            (value) => String(value.scan_id) === String(scanId)
        );
        if (!measurement || !scan) {
            return;
        }
        await this.execute('measurement', async () => {
            const data = await this.pineai.fetchWorkflowScan(scan);
            this.flow.rememberRawScan(scan, data);
            this.flow.selectScan(measurement.measurement_id, String(scan.scan_id));
        }, `Saved Recon scan ${scan.scan_id} loaded into session memory.`);
    }

    async refreshSavedScans(): Promise<void> {
        await this.execute('measurement', async () => {
            await this.pineai.refreshScans();
        }, 'Saved Recon scan list refreshed.');
    }

    async resolveMeasurement(): Promise<void> {
        const measurement = this.currentMeasurement;
        const selection = measurement
            ? this.flow.selectedScan(measurement.measurement_id) : null;
        if (!measurement || !selection) {
            this.flow.setError('measurement', {
                code: 'saved_scan_required',
                message: 'Load a saved Recon scan for the current measurement.'
            });
            return;
        }
        await this.runMutation(
            'measurement',
            () => this.audit.resolveAuditMeasurement(
                this.assessment.assessment_id,
                this.assessment.revision,
                measurement,
                selection.data,
                this.scanMetadata(selection.scan)
            ),
            'Saved Recon scan resolved. Review the result before comparison.'
        );
    }

    async saveComparison(): Promise<void> {
        const measurement = this.currentMeasurement;
        if (!measurement) {
            return;
        }
        await this.runMutation(
            'measurement',
            () => this.audit.saveAuditMeasurementComparison(
                this.assessment.assessment_id,
                this.assessment.revision,
                measurement
            ),
            'Deterministic comparison saved.'
        );
    }

    async retryMeasurement(): Promise<void> {
        const measurement = this.currentMeasurement;
        if (!measurement || measurement.status !== 'failed') {
            return;
        }
        await this.runMutation(
            'measurement',
            () => this.audit.retryAuditMeasurement(
                this.assessment.assessment_id,
                this.assessment.revision,
                measurement
            ),
            `Retry prepared from ${measurement.failed_stage || 'failed'} stage.`
        );
    }

    async generateReport(): Promise<void> {
        if (!this.terminalRun) {
            this.flow.setError('report', {
                code: 'audit_run_not_sealed',
                message: 'Complete or cancel the run before generating a report.'
            });
            return;
        }
        await this.execute('report', async () => {
            this.reportResult = await this.audit.generateAuditRunReport(
                this.assessment.assessment_id,
                this.reportFormat,
                this.privacyProfile
            );
        }, 'Deterministic report generated without changing AuditRun state.');
    }

    downloadReport(): void {
        this.audit.downloadReport(this.reportResult);
    }

    measurementPointName(measurement: AuditMeasurement): string {
        const point = this.audit.pointForMeasurement(measurement);
        return point ? point.location_label : measurement.measurement_point_id;
    }

    profileId(profile: MeasurementProfile): string {
        return this.pineai.measurementProfileId(profile);
    }

    profileVersionId(profile: MeasurementProfile): string {
        return profile ? profile.version_id || '' : '';
    }

    baselineId(baseline: BaselineVersion): string {
        return this.pineai.baselineId(baseline);
    }

    bytes(value: number): string {
        if (value === null || value === undefined) {
            return '—';
        }
        const units = ['B', 'KiB', 'MiB', 'GiB'];
        let amount = value;
        let index = 0;
        while (amount >= 1024 && index < units.length - 1) {
            amount /= 1024;
            index++;
        }
        return `${amount.toFixed(index ? 1 : 0)} ${units[index]}`;
    }

    get availableProfiles(): MeasurementProfile[] {
        return this.pineai.measurementProfiles.filter(
            (profile) => profile.status !== 'archived' &&
                !!this.profileId(profile) && !!this.profileVersionId(profile)
        );
    }

    get availableBaselines(): BaselineVersion[] {
        return this.pineai.baselines.filter(
            (baseline) => !!this.baselineId(baseline)
        );
    }

    private updateAssignment(pointId: string): void {
        const profile = this.availableProfiles.find(
            (candidate) => this.profileId(candidate) ===
                this.profileByPoint[pointId]
        );
        const baselineId = this.baselineByPoint[pointId] || '';
        if (!profile || !baselineId) {
            return;
        }
        const value: AuditRunAssignmentRequest = {
            measurement_point_id: pointId,
            measurement_profile_id: this.profileId(profile),
            measurement_profile_version_id: this.profileVersionId(profile),
            baseline_version_id: baselineId
        };
        this.flow.setAssignment(value);
    }

    private async runMutation(
        area: string,
        action: () => Promise<any>,
        message: string
    ): Promise<void> {
        await this.execute(area, async () => {
            const result = await action();
            await this.syncAssessmentRevision(result);
            if (this.run) {
                this.selectedRunId = this.run.audit_run_id;
            }
            this.terminalConfirmed = false;
        }, message);
    }

    private async syncAssessmentRevision(result: any): Promise<void> {
        if (!this.assessment) {
            return;
        }
        const returned = result && result.assessment;
        if (returned && typeof returned.revision === 'number') {
            this.pineai.activeAssessment = Object.assign(
                {}, this.pineai.activeAssessment, returned
            );
            return;
        }
        const revision = result && (
            result.assessment_revision || result.current_assessment_revision
        );
        if (typeof revision === 'number') {
            this.pineai.activeAssessment = Object.assign(
                {}, this.pineai.activeAssessment, {revision}
            );
            return;
        }
        await this.pineai.selectAssessment(
            this.assessment.assessment_id,
            true
        );
    }

    private scanMetadata(scan: ReconScan): any {
        return {
            scan_id: scan.scan_id,
            date: scan.date || null,
            scan_time: scan.scan_time || null
        };
    }

    private async execute(
        area: string,
        operation: () => Promise<void>,
        success: string
    ): Promise<void> {
        this.flow.clearFeedback(area);
        try {
            await operation();
            this.flow.setMessage(area, success);
        } catch (error) {
            const normalized = this.audit.normalizeError(error);
            this.flow.setError(area, normalized);
            if (normalized.code === 'revision_conflict' && this.assessment) {
                try {
                    await this.pineai.selectAssessment(
                        this.assessment.assessment_id,
                        true
                    );
                    if (this.selectedRunId) {
                        await this.audit.selectAuditRun(
                            this.assessment.assessment_id,
                            this.selectedRunId
                        );
                    }
                } catch (_) {
                    // Keep the original conflict visible. A manual refresh remains available.
                }
            }
        }
    }
}
