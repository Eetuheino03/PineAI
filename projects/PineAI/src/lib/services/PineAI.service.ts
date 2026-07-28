import { Injectable } from '@angular/core';
import { ApiService } from './api.service';
import {
    ActivityEntry,
    Assessment,
    BaselineVersion,
    Finding,
    FrontendError,
    MeasurementContext,
    PanelErrorMap,
    PineAISettings,
    ReconScan,
    ReconStatus
} from '../models';

@Injectable({
    providedIn: 'root'
})
export class PineAIService {
    health: any = null;
    settings: PineAISettings = {
        language: 'en',
        share_ssids: false,
        api_key_configured: false,
        api_key_source: 'none'
    };
    capabilities: any = null;
    reconStatus: ReconStatus = null;
    scans: ReconScan[] = [];
    selectedScan: ReconScan = null;
    selectedScanData: any = null;
    resolvedScan: any = null;
    assessments: Assessment[] = [];
    activeAssessment: Assessment = null;
    baselines: BaselineVersion[] = [];
    activeBaselineVersion: any = null;
    comparison: any = null;
    analysis: any = null;
    findings: Finding[] = [];
    aiPreview: any = null;
    aiAnalysis: any = null;
    report: any = null;
    activity: ActivityEntry[] = [];
    panelErrors: PanelErrorMap = {};
    initializing = false;
    initialized = false;

    measurementContext: MeasurementContext = {
        location_id: '',
        measurement_point_id: '',
        scan_profile_id: '',
        radio_profile_id: '',
        interface: '',
        declared_channels: []
    };
    measurementContextByScan: { [scanId: string]: MeasurementContext } = {};

    constructor(private api: ApiService) {}

    private module<T>(action: string, values: any = {}): Promise<T> {
        return this.api.moduleRequest<T>(
            Object.assign({module: 'PineAI', action}, values)
        );
    }

    error(error: any): FrontendError {
        if (error && typeof error.code === 'string') {
            return {
                code: error.code,
                message: error.message || error.safe_message || error.code
            };
        }
        if (error && error.error && typeof error.error.code === 'string') {
            return {
                code: error.error.code,
                message: error.error.message || error.error.code
            };
        }
        if (error && typeof error.message === 'string') {
            return {code: 'request_failed', message: error.message};
        }
        return {code: 'request_failed', message: 'The request failed.'};
    }

    errorText(error: any): string {
        const value = this.error(error);
        return `${value.code}: ${value.message}`;
    }

    setPanelError(panel: string, error: any): void {
        this.panelErrors[panel] = this.error(error);
        this.panelErrors = Object.assign({}, this.panelErrors);
    }

    clearPanelError(panel: string): void {
        if (this.panelErrors[panel]) {
            delete this.panelErrors[panel];
            this.panelErrors = Object.assign({}, this.panelErrors);
        }
    }

    log(
        level: ActivityEntry['level'],
        title: string,
        detail: string = ''
    ): void {
        this.activity.unshift({
            time: new Date().toISOString(),
            level,
            title,
            detail
        });
        this.activity = this.activity.slice(0, 100);
    }

    private settle(panel: string, operation: () => Promise<any>): Promise<void> {
        return operation().then(() => {
            this.clearPanelError(panel);
        }).catch((error) => {
            this.setPanelError(panel, error);
            const failure = this.error(error);
            this.log('warning', `${panel} unavailable`, `${failure.code}: ${failure.message}`);
        });
    }

    async initialize(): Promise<void> {
        if (this.initializing) {
            return;
        }
        this.initializing = true;
        this.initialized = false;
        try {
            // Health is the only hard dependency. Everything else degrades locally.
            await this.refreshHealth();
            await Promise.all([
                this.settle('settings', () => this.refreshSettings()),
                this.settle('capabilities', () => this.refreshCapabilities()),
                this.settle('recon', async () => {
                    await Promise.all([this.refreshReconStatus(), this.refreshScans()]);
                }),
                this.settle('assessments', () => this.refreshAssessments())
            ]);
            this.initialized = true;
            this.log(
                'success',
                'PineAI ready',
                'Baseline & Drift is available. Optional services may remain offline.'
            );
        } catch (error) {
            const failure = this.error(error);
            this.log('error', 'Backend initialization failed', `${failure.code}: ${failure.message}`);
            throw error;
        } finally {
            this.initializing = false;
        }
    }

    async refreshHealth(): Promise<any> {
        this.health = await this.module<any>('health');
        return this.health;
    }

    async refreshSettings(): Promise<PineAISettings> {
        const result = await this.module<PineAISettings>('get_settings');
        this.settings = Object.assign({}, this.settings, result || {});
        return this.settings;
    }

    async refreshCapabilities(): Promise<any> {
        this.capabilities = await this.module<any>('assurance_capabilities');
        return this.capabilities;
    }

    async saveSettings(language: 'en' | 'fi', shareSsids: boolean): Promise<PineAISettings> {
        const result = await this.module<PineAISettings>('update_settings', {
            settings: {language, share_ssids: shareSsids}
        });
        this.settings = Object.assign({}, this.settings, result || {});
        this.clearPanelError('settings');
        this.log('success', 'Settings saved', 'Language and privacy settings updated.');
        return this.settings;
    }

    async setApiKey(
        apiKey: string,
        secure: boolean,
        insecureAcknowledged: boolean
    ): Promise<void> {
        await this.module<any>('set_openai_api_key', {
            api_key: apiKey,
            transport_secure: secure,
            insecure_transport_acknowledged: insecureAcknowledged
        });
        await this.refreshSettings();
        this.log('success', 'OpenAI key stored', 'The key was sent once and is not retained by the browser.');
    }

    async deleteApiKey(): Promise<void> {
        await this.module<any>('delete_openai_api_key');
        await this.refreshSettings();
        this.log('warning', 'Managed OpenAI key removed');
    }

    async refreshReconStatus(): Promise<ReconStatus> {
        this.reconStatus = await this.api.nativeGet<ReconStatus>('/api/recon/status');
        this.clearPanelError('recon');
        return this.reconStatus;
    }

    async refreshScans(): Promise<ReconScan[]> {
        const result: any = await this.api.nativeGet<any>('/api/recon/scans');
        const values = Array.isArray(result)
            ? result
            : result && Array.isArray(result.scans) ? result.scans : [];
        this.scans = values.slice().sort(
            (left, right) => String(right.date || '').localeCompare(String(left.date || ''))
        );
        this.clearPanelError('recon');
        return this.scans;
    }

    async loadScan(scan: ReconScan): Promise<any> {
        this.selectedScan = scan;
        this.selectedScanData = await this.api.nativeGet<any>(
            `/api/recon/scans/${encodeURIComponent(String(scan.scan_id))}`
        );
        this.resolvedScan = null;
        this.comparison = null;
        this.analysis = null;
        this.aiPreview = null;
        this.aiAnalysis = null;
        this.report = null;
        const scanIdStr = String(scan.scan_id);
        if (!this.measurementContextByScan[scanIdStr]) {
            this.measurementContextByScan[scanIdStr] = {
                location_id: '',
                measurement_point_id: '',
                scan_profile_id: '',
                radio_profile_id: '',
                interface: '',
                declared_channels: []
            };
        }
        this.measurementContext = this.measurementContextByScan[scanIdStr];
        this.clearPanelError('recon');
        this.log('success', 'Recon scan loaded', `Scan ${scan.scan_id} is ready.`);
        return this.selectedScanData;
    }

    private requireScan(): void {
        if (!this.selectedScan || !this.selectedScanData) {
            throw {code: 'scan_required', message: 'Load a saved Recon scan first.'};
        }
    }

    scanMetadata(overrideContext?: MeasurementContext): any {
        const source: any = this.selectedScan || {};
        const allowed = [
            'scan_id',
            'id',
            'date',
            'started_at',
            'completed_at',
            'scan_time',
            'duration',
            'coverage',
            'source',
            'label'
        ];
        const result: any = {};
        for (const field of allowed) {
            if (source[field] !== undefined && source[field] !== null) {
                result[field] = Array.isArray(source[field])
                    ? source[field].slice() : source[field];
            }
        }
        const ctx = overrideContext || this.measurementContext;
        if (ctx) {
            const mc: any = {};
            if (ctx.location_id) mc.location_id = ctx.location_id;
            if (ctx.measurement_point_id) mc.measurement_point_id = ctx.measurement_point_id;
            if (ctx.scan_profile_id) mc.scan_profile_id = ctx.scan_profile_id;
            if (ctx.radio_profile_id) mc.radio_profile_id = ctx.radio_profile_id;
            if (ctx.interface) mc.interface = ctx.interface;
            if (ctx.declared_channels && ctx.declared_channels.length > 0) {
                mc.declared_channels = ctx.declared_channels;
            }
            if (Object.keys(mc).length > 0) {
                result.measurement_context = mc;
            }
        }
        return result;
    }

    reasonLabel(reason: string, lang: 'en' | 'fi' = 'fi'): string {
        const fiMap: {[key: string]: string} = {
            'legacy_baseline_missing_measurement_context': 'Vertailukohtana vanha baseline (ei mittauskontekstia)',
            'measurement_context_unknown': 'Mittauskonteksti puuttuu tai on tuntematon (location_id / measurement_point_id)',
            'location_mismatch': 'Sijainti (location_id) ei täsmää baselineen',
            'measurement_point_mismatch': 'Mittauspiste (measurement_point_id) ei täsmää baselineen',
            'position_confirmation_different': 'Laite- tai antenniasento poikkeaa baselinesta',
            'radio_profile_mismatch': 'Radio/rauta-profiili ei täsmää baselineen',
            'radio_profile_unknown': 'Radio-ohjaimen profiili on tuntematon',
            'radio_interface_mismatch': 'Radio/rauta-rajapinta ei täsmää baselineen',
            'scan_profile_mismatch': 'Skannausprofiili poikkeaa baselinesta',
            'channel_coverage_unknown': 'Kanavakattavuus on tuntematon (ilmoittamaton kanalista)',
            'declared_channels_do_not_cover_baseline_channels': 'Määritellyt kanavat eivät kata baselinen kanavia',
            'current_scan_contains_no_access_points': 'Nykyisessä skannauksessa ei havaittu yhtään tukiasemaa',
            'current_scan_does_not_cover_baseline_bands': 'Skannaus ei kata baselinen taajuusalueita',
            'band_coverage_is_incomplete': 'Taajuusalueen kattavuus on puutteellinen',
            'scan_duration_is_unknown': 'Skannauksen kesto on tuntematon',
            'current_scan_is_materially_shorter': 'Skannauksen kesto on huomattavasti baselinea lyhyempi',
            'low_comparison_quality_score': 'Vertailun laatupistemäärä on liian alhainen (< 75%)',
            'low_overall_comparison_quality_score': 'Vertailun kokonaislaatu on liian alhainen (< 75%)',
            'low_baseline_ap_detection_ratio': 'Ankkuri-tukiasemien havaintosuhde liian alhainen (< 50%)',
            'baseline_ap_detection_ratio_too_low': 'Baselinen ankkuri-tukiasemien havaintosuhde liian alhainen (< 50%)',
            'signal_profile_changed_materially': 'Signaaliprofiilissa merkittävä muutos (> 15 dB)',
            'essential_measurement_context_missing': 'Mittaustietoja tai puuttuvia kanavia ei voida vahvistaa'
        };
        const enMap: {[key: string]: string} = {
            'legacy_baseline_missing_measurement_context': 'Legacy baseline without measurement context',
            'measurement_context_unknown': 'Measurement context missing or unknown (location_id / measurement_point_id)',
            'location_mismatch': 'Location ID does not match baseline',
            'measurement_point_mismatch': 'Measurement point ID does not match baseline',
            'position_confirmation_different': 'Position or antenna orientation differs',
            'radio_profile_mismatch': 'Radio profile does not match baseline',
            'radio_profile_unknown': 'Radio profile is unknown',
            'radio_interface_mismatch': 'Radio/interface does not match baseline',
            'scan_profile_mismatch': 'Scan profile differs from baseline',
            'channel_coverage_unknown': 'Channel coverage is unknown (undeclared channels)',
            'declared_channels_do_not_cover_baseline_channels': 'Declared channels do not cover candidate channels',
            'current_scan_contains_no_access_points': 'Current scan contains no access points',
            'current_scan_does_not_cover_baseline_bands': 'Current scan does not cover baseline frequency bands',
            'band_coverage_is_incomplete': 'Band coverage is incomplete',
            'scan_duration_is_unknown': 'Scan duration is unknown',
            'current_scan_is_materially_shorter': 'Scan duration is materially shorter than baseline',
            'low_comparison_quality_score': 'Comparison quality score is too low (< 75%)',
            'low_overall_comparison_quality_score': 'Overall comparison quality score is too low (< 75%)',
            'low_baseline_ap_detection_ratio': 'Baseline anchor AP detection ratio is too low (< 50%)',
            'baseline_ap_detection_ratio_too_low': 'Baseline anchor AP detection ratio is too low (< 50%)',
            'signal_profile_changed_materially': 'Signal profile has changed materially (> 15 dB)',
            'essential_measurement_context_missing': 'Essential measurement context missing'
        };
        if (lang === 'fi') {
            return fiMap[reason] || reason;
        }
        return enMap[reason] || reason;
    }

    async resolveSelectedScan(): Promise<any> {
        this.requireScan();
        this.resolvedScan = await this.module<any>('resolve_recon', {
            scan: this.selectedScanData,
            scan_metadata: this.scanMetadata()
        });
        this.clearPanelError('assets');
        this.log('success', 'Assets resolved', `Scan ${this.selectedScan.scan_id} was normalized offline.`);
        return this.resolvedScan;
    }

    async refreshAssessments(includeArchived: boolean = false): Promise<Assessment[]> {
        const result: any = await this.module<any>('list_assessments', {
            include_archived: includeArchived
        });
        this.assessments = Array.isArray(result)
            ? result
            : result && Array.isArray(result.assessments) ? result.assessments : [];
        this.clearPanelError('assessments');
        return this.assessments;
    }

    async selectAssessment(
        assessmentId: string,
        preserveWorkflow: boolean = false
    ): Promise<Assessment> {
        const result: any = await this.module<any>('get_assessment', {
            assessment_id: assessmentId,
            after_sequence: 0,
            limit: 100
        });
        this.activeAssessment = result && result.assessment
            ? Object.assign({}, result.assessment, {events: result.events || result.assessment.events})
            : result;
        this.baselines = [];
        this.activeBaselineVersion = null;
        this.findings = [];
        if (!preserveWorkflow) {
            this.comparison = null;
            this.analysis = null;
            this.aiPreview = null;
            this.aiAnalysis = null;
            this.report = null;
        }
        await Promise.all([
            this.settle('baselines', () => this.refreshBaselines()),
            this.settle('findings', () => this.refreshFindings())
        ]);
        return this.activeAssessment;
    }

    async createAssessment(value: {
        name: string;
        location?: string;
        notes?: string;
    }): Promise<Assessment> {
        const result: any = await this.module<any>('create_assessment', {
            assessment: value
        });
        this.activeAssessment = result && result.assessment ? result.assessment : result;
        await this.refreshAssessments();
        await this.selectAssessment(this.activeAssessment.assessment_id);
        this.log('success', 'Assessment created', this.activeAssessment.name);
        return this.activeAssessment;
    }

    async updateAssessment(changes: any): Promise<Assessment> {
        this.requireAssessment();
        const assessmentId = this.activeAssessment.assessment_id;
        try {
            const result: any = await this.module<any>('update_assessment', {
                assessment_id: assessmentId,
                expected_revision: this.activeAssessment.revision,
                changes
            });
            this.activeAssessment = result && result.assessment ? result.assessment : result;
            await this.refreshAssessments();
            await this.selectAssessment(assessmentId, true);
            this.report = null;
            this.log('success', 'Assessment updated', this.activeAssessment.name);
            return this.activeAssessment;
        } catch (error) {
            if (this.error(error).code === 'revision_conflict') {
                await this.selectAssessment(assessmentId);
            }
            throw error;
        }
    }

    async archiveAssessment(): Promise<void> {
        this.requireAssessment();
        const assessmentId = this.activeAssessment.assessment_id;
        try {
            await this.module<any>('archive_assessment', {
                assessment_id: assessmentId,
                expected_revision: this.activeAssessment.revision
            });
            this.log('warning', 'Assessment archived', this.activeAssessment.name);
            this.activeAssessment = null;
            this.baselines = [];
            this.activeBaselineVersion = null;
            this.findings = [];
            this.comparison = null;
            this.analysis = null;
            this.aiPreview = null;
            this.aiAnalysis = null;
            this.report = null;
            await this.refreshAssessments();
        } catch (error) {
            if (this.error(error).code === 'revision_conflict') {
                await this.selectAssessment(assessmentId);
            }
            throw error;
        }
    }

    private requireAssessment(): void {
        if (!this.activeAssessment) {
            throw {code: 'assessment_required', message: 'Create or select an assessment first.'};
        }
    }

    private requireResolvedScan(): void {
        this.requireScan();
        if (!this.resolvedScan) {
            throw {code: 'resolved_scan_required', message: 'Resolve the selected scan first.'};
        }
    }

    async refreshBaselines(): Promise<BaselineVersion[]> {
        this.requireAssessment();
        const result: any = await this.module<any>('list_baseline_versions', {
            assessment_id: this.activeAssessment.assessment_id
        });
        this.activeBaselineVersion = result && result.active_baseline_version
            ? result.active_baseline_version : null;
        this.baselines = Array.isArray(result)
            ? result
            : result && Array.isArray(result.baseline_versions)
                ? result.baseline_versions
                : result && Array.isArray(result.baselines) ? result.baselines : [];
        this.clearPanelError('baselines');
        return this.baselines;
    }

    async createBaselineVersion(label: string = ''): Promise<any> {
        this.requireAssessment();
        this.requireResolvedScan();
        const assessmentId = this.activeAssessment.assessment_id;
        const result: any = await this.module<any>('create_baseline_version', {
            assessment_id: assessmentId,
            expected_revision: this.activeAssessment.revision,
            scan: this.selectedScanData,
            scan_metadata: this.scanMetadata(),
            label
        });
        if (result && result.assessment) {
            this.activeAssessment = result.assessment;
        }
        await this.selectAssessment(assessmentId);
        this.log('success', 'Baseline version created', label || 'Immutable baseline candidate saved.');
        return result;
    }

    baselineId(value: any): string {
        if (typeof value === 'string') {
            return value;
        }
        return value
            ? value.baseline_version_id || value.baseline_id ||
              value.baseline_version || value.version_id || ''
            : '';
    }

    async activateBaselineVersion(baselineVersionId: string): Promise<any> {
        this.requireAssessment();
        const assessmentId = this.activeAssessment.assessment_id;
        const result = await this.module<any>('activate_baseline_version', {
            assessment_id: assessmentId,
            expected_revision: this.activeAssessment.revision,
            baseline_version: baselineVersionId
        });
        await this.selectAssessment(assessmentId);
        this.log('success', 'Baseline activated', baselineVersionId);
        return result;
    }

    async compareSelectedScan(): Promise<any> {
        this.requireAssessment();
        this.requireResolvedScan();
        this.comparison = await this.module<any>('compare_recon', {
            assessment_id: this.activeAssessment.assessment_id,
            scan: this.selectedScanData,
            scan_metadata: this.scanMetadata()
        });
        this.clearPanelError('assets');
        this.log('success', 'Comparison complete', this.comparabilityLabel(this.comparison));
        return this.comparison;
    }

    async analyzeSelectedScan(): Promise<any> {
        this.requireAssessment();
        this.requireResolvedScan();
        const assessmentId = this.activeAssessment.assessment_id;
        try {
            this.analysis = await this.module<any>('analyze_recon', {
                assessment_id: assessmentId,
                expected_revision: this.activeAssessment.revision,
                scan: this.selectedScanData,
                scan_metadata: this.scanMetadata()
            });
            if (this.analysis && this.analysis.assessment) {
                this.activeAssessment = this.analysis.assessment;
            }
            this.aiPreview = null;
            this.aiAnalysis = null;
            this.report = null;
            this.comparison = this.analysis.comparison || this.analysis;
            await this.refreshAssessments();
            await this.selectAssessment(assessmentId, true);
            this.comparison = this.analysis.comparison || this.analysis;
            await this.refreshFindings();
            this.log('success', 'Analysis saved', this.comparabilityLabel(this.analysis));
            return this.analysis;
        } catch (error) {
            if (this.error(error).code === 'revision_conflict') {
                await this.selectAssessment(assessmentId);
            }
            throw error;
        }
    }

    comparability(value: any): any {
        if (!value) {
            return null;
        }
        if (value.comparability) {
            return value.comparability;
        }
        if (value.diff && value.diff.comparability) {
            return value.diff.comparability;
        }
        if (value.comparison && value.comparison !== value) {
            const nested = this.comparability(value.comparison);
            if (nested) {
                return nested;
            }
        }
        if (value.result && value.result !== value) {
            return this.comparability(value.result);
        }
        return null;
    }

    comparabilityLabel(value: any): string {
        const comparable = this.comparability(value);
        return comparable
            ? comparable.status || comparable.state || String(comparable)
            : 'unknown';
    }

    async refreshFindings(): Promise<Finding[]> {
        this.requireAssessment();
        const result: any = await this.module<any>('list_findings', {
            assessment_id: this.activeAssessment.assessment_id
        });
        this.findings = Array.isArray(result)
            ? result
            : result && Array.isArray(result.findings) ? result.findings : [];
        this.clearPanelError('findings');
        return this.findings;
    }

    async updateFinding(
        findingId: string,
        status: 'open' | 'acknowledged' | 'false_positive',
        note: string = ''
    ): Promise<any> {
        this.requireAssessment();
        const assessmentId = this.activeAssessment.assessment_id;
        try {
            const result = await this.module<any>('update_finding', {
                assessment_id: assessmentId,
                expected_revision: this.activeAssessment.revision,
                finding_id: findingId,
                status,
                note
            });
            await this.selectAssessment(assessmentId, true);
            await this.refreshFindings();
            this.aiPreview = null;
            this.aiAnalysis = null;
            this.report = null;
            this.log('success', 'Finding updated', `${findingId}: ${status}`);
            return result;
        } catch (error) {
            if (this.error(error).code === 'revision_conflict') {
                await this.selectAssessment(assessmentId, true);
                await this.refreshFindings();
            }
            throw error;
        }
    }

    private aiOptions(language?: 'en' | 'fi'): any {
        return {
            language: language || this.settings.language || 'en',
            share_ssids: !!this.settings.share_ssids
        };
    }

    async prepareAiAnalysis(
        findingIds: string[],
        task: string,
        language?: 'en' | 'fi'
    ): Promise<any> {
        this.requireAssessment();
        this.aiPreview = await this.module<any>('prepare_ai_analysis', {
            assessment_id: this.activeAssessment.assessment_id,
            comparison_id: this.comparisonId(),
            finding_ids: findingIds,
            options: this.aiOptions(language)
        });
        return this.aiPreview;
    }

    async generateAiAnalysis(
        findingIds: string[],
        task: string,
        language?: 'en' | 'fi'
    ): Promise<any> {
        this.requireAssessment();
        this.aiAnalysis = await this.module<any>('generate_ai_analysis', {
            assessment_id: this.activeAssessment.assessment_id,
            comparison_id: this.comparisonId(),
            finding_ids: findingIds,
            options: this.aiOptions(language)
        });
        this.clearPanelError('ai');
        this.log('success', 'Optional AI analysis complete', task);
        return this.aiAnalysis;
    }

    async generateReport(
        format: 'json' | 'html',
        includeAi: boolean
    ): Promise<any> {
        this.requireAssessment();
        const comparisonId = this.comparisonId();
        this.report = await this.module<any>('generate_report', {
            assessment_id: this.activeAssessment.assessment_id,
            comparison_id: comparisonId,
            format,
            ai_analysis: includeAi ? this.aiAnalysisValue() : null
        });
        this.clearPanelError('reports');
        this.log('success', `${format.toUpperCase()} report generated`, this.report.filename || '');
        return this.report;
    }

    downloadReport(result: any): void {
        if (!result) {
            return;
        }
        const filename = result.filename || 'pineai-report.json';
        if (result.path || result.file_path) {
            this.api.APIDownload(result.path || result.file_path, filename);
            return;
        }
        const content = result.content !== undefined
            ? result.content
            : result.report !== undefined ? result.report : result;
        const mime = filename.toLowerCase().endsWith('.html')
            ? 'text/html;charset=utf-8'
            : 'application/json;charset=utf-8';
        const text = typeof content === 'string'
            ? content : JSON.stringify(content, null, 2);
        const blob = new Blob([text], {type: mime});
        const url = window.URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        document.body.appendChild(anchor);
        anchor.style.display = 'none';
        anchor.href = url;
        anchor.download = filename;
        anchor.click();
        window.URL.revokeObjectURL(url);
        anchor.remove();
    }

    activeBaselineId(): string {
        const assessmentValue = this.activeAssessment
            ? this.activeAssessment.active_baseline_version ||
              this.activeAssessment.active_baseline_version_id ||
              this.activeAssessment.active_baseline_id
            : '';
        return assessmentValue || this.baselineId(this.activeBaselineVersion);
    }

    assessmentMutable(): boolean {
        return !!this.activeAssessment &&
            this.activeAssessment.status !== 'archived';
    }

    comparisonId(): string {
        const value = this.analysis && this.analysis.comparison
            ? this.analysis.comparison
            : this.comparison;
        const id = value
            ? value.comparison_id || value.analysis_id || value.snapshot_id
            : '';
        const stored = this.activeAssessment &&
            Array.isArray(this.activeAssessment.comparisons) &&
            this.activeAssessment.comparisons.length
            ? this.activeAssessment.comparisons[0].comparison_id
            : '';
        const selected = id || stored;
        if (!selected) {
            throw {
                code: 'comparison_required',
                message: 'Save a comparison before requesting AI text or a report.'
            };
        }
        return selected;
    }

    hasComparison(): boolean {
        try {
            return !!this.comparisonId();
        } catch (_error) {
            return false;
        }
    }

    aiAnalysisValue(): any {
        return this.aiAnalysis && this.aiAnalysis.analysis
            ? this.aiAnalysis.analysis : null;
    }

    findingCounts(): {[status: string]: number} {
        const counts: {[status: string]: number} = {
            open: 0,
            acknowledged: 0,
            false_positive: 0,
            resolved: 0
        };
        for (const finding of this.findings) {
            counts[finding.status] = (counts[finding.status] || 0) + 1;
        }
        return counts;
    }
}
