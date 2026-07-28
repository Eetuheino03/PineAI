import {Component} from '@angular/core';
import {
    AssuranceProfile,
    MeasurementProfile,
    ReconScan,
    ReportScope,
    WorkflowState,
    WorkflowStepKey
} from '../models';
import {PineAIService} from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-guided-assessment',
    templateUrl: './guided-assessment.component.html',
    styleUrls: ['./shared.css']
})
export class GuidedAssessmentComponent {
    readonly steps: WorkflowStepKey[] = [
        'assessment',
        'measurement_profile',
        'recon_scans',
        'baseline_comparison',
        'inventory_policy',
        'analysis_evidence',
        'report'
    ];

    assessmentName = '';
    assessmentLocation = '';
    selectedAssessmentId = '';
    selectedProfileId = '';
    baselineLabel = '';
    maxSourceAgeHours = 24;
    inventoryCsv = '';
    assuranceLabel = '';
    coverageMode: 'partial' | 'authoritative' = 'partial';
    reportFormat: 'json' | 'html' = 'html';
    reportScopeType:
        'comparison' | 'assessment_current' | 'assessment_history' =
        'comparison';
    privacyProfile: 'local_full' | 'share_safe' = 'local_full';
    errors: {[step: string]: string} = {};
    messages: {[step: string]: string} = {};

    constructor(public pineai: PineAIService) {}

    get state(): WorkflowState {
        return this.pineai.workflow.snapshot;
    }

    get selectedIndex(): number {
        const index = this.steps.indexOf(this.state.current_step);
        return index < 0 ? 0 : index;
    }

    get selectedScans(): number {
        return this.state.selected_scans.filter((value) => value.loaded).length;
    }

    get baselineMode(): boolean {
        return this.state.mode === 'baseline';
    }

    get activeProfile(): MeasurementProfile {
        return this.pineai.selectedMeasurementProfile;
    }

    get activeAssuranceProfile(): AssuranceProfile {
        return this.pineai.assuranceProfile;
    }

    stepState(step: WorkflowStepKey): string {
        return this.state.step_states[step] || 'blocked';
    }

    canProceed(step: WorkflowStepKey): boolean {
        return this.pineai.workflow.canProceed(step);
    }

    selectStepIndex(index: number): void {
        if (index >= 0 && index < this.steps.length) {
            this.pineai.workflow.setCurrentStep(this.steps[index]);
        }
    }

    go(step: WorkflowStepKey): void {
        this.pineai.workflow.setCurrentStep(step);
    }

    async selectAssessment(): Promise<void> {
        if (!this.selectedAssessmentId) {
            this.setError(
                'assessment',
                'assessment_required: Select an assessment.'
            );
            return;
        }
        await this.run(
            'assessment',
            () => this.pineai.selectAssessment(this.selectedAssessmentId),
            'Assessment selected. Continue with a measurement profile.'
        );
    }

    async createAssessment(): Promise<void> {
        if (!this.assessmentName.trim()) {
            this.setError(
                'assessment',
                'validation_error: Assessment name is required.'
            );
            return;
        }
        await this.run(
            'assessment',
            () => this.pineai.createAssessment({
                name: this.assessmentName.trim(),
                location: this.assessmentLocation.trim()
            }),
            'Assessment created. No baseline or analysis was created automatically.'
        );
        if (this.pineai.activeAssessment) {
            this.selectedAssessmentId =
                this.pineai.activeAssessment.assessment_id;
        }
    }

    selectMeasurementProfile(profileId: string): void {
        this.selectedProfileId = profileId;
        const profile = this.pineai.measurementProfiles.find(
            (value) => this.pineai.measurementProfileId(value) === profileId
        ) || null;
        this.pineai.applyMeasurementProfile(profile);
        this.clearStep('measurement_profile');
        if (profile) {
            this.messages.measurement_profile =
                `Profile "${profile.name}" revision ${profile.revision} copied into this run.`;
        }
    }

    async refreshProfiles(): Promise<void> {
        await this.run(
            'measurement_profile',
            () => this.pineai.refreshMeasurementProfiles(),
            'Measurement profile capabilities refreshed.'
        );
    }

    scanSelected(scan: ReconScan): boolean {
        return this.state.selected_scans.some(
            (value) => value.scan_id === String(scan.scan_id)
        );
    }

    scanSelectionDisabled(scan: ReconScan): boolean {
        if (this.scanSelected(scan)) {
            return false;
        }
        return this.baselineMode && this.state.selected_scans.length >= 5;
    }

    async toggleScan(scan: ReconScan, checked: boolean): Promise<void> {
        const id = String(scan.scan_id);
        this.clearStep('recon_scans');
        if (!checked) {
            this.pineai.workflow.removeScan(id);
            return;
        }
        if (!this.baselineMode) {
            const existing = this.state.selected_scans.slice();
            existing.forEach((value) =>
                this.pineai.workflow.removeScan(value.scan_id)
            );
        }
        await this.run(
            'recon_scans',
            async () => {
                await this.pineai.fetchWorkflowScan(scan);
                if (!this.baselineMode) {
                    this.pineai.useWorkflowScan(id);
                }
            },
            `Saved Recon scan ${id} loaded into session memory.`
        );
    }

    async refreshScans(): Promise<void> {
        await this.run(
            'recon_scans',
            () => this.pineai.refreshScans(),
            'Saved Recon scans refreshed.'
        );
    }

    async previewBaseline(): Promise<void> {
        await this.run(
            'baseline_comparison',
            () => this.pineai.previewConsensusBaseline(
                this.maxSourceAgeHours
            ),
            'Consensus preview ready. No baseline version was created.'
        );
    }

    async createBaseline(): Promise<void> {
        await this.run(
            'baseline_comparison',
            () => this.pineai.createConsensusBaselineVersion(
                this.baselineLabel,
                this.maxSourceAgeHours
            ),
            'Immutable consensus baseline version created. It is not active yet.'
        );
    }

    async activateBaseline(profile: any): Promise<void> {
        const id = this.pineai.baselineId(profile);
        if (!id || !window.confirm(
            `Activate baseline "${id}" as the authoritative reference?`
        )) {
            return;
        }
        await this.run(
            'baseline_comparison',
            async () => {
                await this.pineai.activateBaselineVersion(id);
                this.pineai.workflow.clearSelectedScans();
                this.pineai.workflow.setCurrentStep('recon_scans');
            },
            'Baseline activated. Select one later scan for comparison.'
        );
    }

    async previewComparison(): Promise<void> {
        await this.run(
            'baseline_comparison',
            async () => {
                const selected = this.state.selected_scans.find(
                    (value) => value.loaded
                );
                if (!selected) {
                    throw {
                        code: 'scan_required',
                        message: 'Select one loaded Recon scan.'
                    };
                }
                this.pineai.useWorkflowScan(selected.scan_id);
                await this.pineai.resolveSelectedScan();
                await this.pineai.compareSelectedScan();
            },
            'Read-only comparison preview complete. Findings were not changed.'
        );
    }

    async readInventoryFile(event: Event): Promise<void> {
        const input = event.target as HTMLInputElement;
        const file = input.files && input.files.length
            ? input.files[0] : null;
        if (!file) {
            return;
        }
        if (file.size > 524288) {
            this.setError(
                'inventory_policy',
                'inventory_too_large: CSV files are limited to 512 KiB.'
            );
            input.value = '';
            return;
        }
        const reader = new FileReader();
        reader.onload = () => {
            this.inventoryCsv =
                typeof reader.result === 'string' ? reader.result : '';
            this.clearStep('inventory_policy');
        };
        reader.onerror = () => this.setError(
            'inventory_policy',
            'file_read_failed: The selected CSV could not be read.'
        );
        reader.readAsText(file);
        input.value = '';
    }

    async previewInventory(): Promise<void> {
        await this.run(
            'inventory_policy',
            () => this.pineai.previewInventoryCsv(this.inventoryCsv),
            'Inventory preview prepared. Nothing was activated.'
        );
    }

    async createAssuranceProfile(): Promise<void> {
        await this.run(
            'inventory_policy',
            () => this.pineai.createAssuranceProfileVersion(
                this.assuranceLabel,
                this.coverageMode
            ),
            'Assurance profile version created. Activate it explicitly.'
        );
    }

    async activateAssuranceProfile(profile: AssuranceProfile): Promise<void> {
        const id = this.pineai.assuranceProfileId(profile);
        if (!id || !window.confirm(
            `Activate assurance profile "${id}" for deterministic policy evaluation?`
        )) {
            return;
        }
        await this.run(
            'inventory_policy',
            () => this.pineai.activateAssuranceProfileVersion(profile),
            'Assurance profile activated.'
        );
    }

    confirmInventoryPolicy(): void {
        this.pineai.workflow.confirmAssuranceProfile();
        this.clearStep('inventory_policy');
        this.messages.inventory_policy = this.activeAssuranceProfile
            ? 'Active inventory and policy revision confirmed for this run.'
            : 'No active inventory profile confirmed. Core drift rules remain active.';
    }

    async saveAnalysis(): Promise<void> {
        await this.run(
            'analysis_evidence',
            () => this.pineai.analyzeSelectedScan(),
            'Analysis saved. Finding lifecycle and evidence are now auditable.'
        );
    }

    reportScope(): ReportScope {
        const scope: ReportScope = {
            type: this.reportScopeType,
            include_evidence: true,
            include_inventory_policy: true,
            include_ai: false
        };
        if (this.reportScopeType === 'comparison') {
            scope.comparison_id = this.pineai.hasComparison()
                ? this.pineai.comparisonId() : '';
        }
        return scope;
    }

    async prepareReport(): Promise<void> {
        await this.run(
            'report',
            () => this.pineai.prepareReportScope(
                this.reportScope(),
                this.privacyProfile
            ),
            'Report manifest and privacy scope prepared. No file was generated.'
        );
    }

    async generateReport(): Promise<void> {
        await this.run(
            'report',
            () => this.pineai.generateReport(
                this.reportFormat,
                false,
                this.reportScope(),
                this.privacyProfile
            ),
            'Deterministic report generated.'
        );
    }

    downloadReport(): void {
        this.pineai.downloadReport(this.pineai.report);
    }

    taxonomyCount(kind: string): number {
        const taxonomy = this.pineai.resultTaxonomy();
        if (kind === 'observed_changes') {
            return taxonomy.observed_changes.length;
        }
        if (kind === 'deviations') {
            return taxonomy.deviations.length;
        }
        return taxonomy.security_findings.length;
    }

    private async run(
        step: WorkflowStepKey,
        operation: () => Promise<any>,
        message: string
    ): Promise<void> {
        this.clearStep(step);
        this.pineai.workflow.setBusy(step);
        try {
            await operation();
            this.messages[step] = message;
        } catch (error) {
            this.setError(step, this.pineai.errorText(error));
        } finally {
            this.pineai.workflow.setBusy('');
        }
    }

    private clearStep(step: WorkflowStepKey): void {
        delete this.errors[step];
        delete this.messages[step];
        this.errors = Object.assign({}, this.errors);
        this.messages = Object.assign({}, this.messages);
    }

    private setError(step: WorkflowStepKey, message: string): void {
        this.errors[step] = message;
        this.errors = Object.assign({}, this.errors);
    }
}
