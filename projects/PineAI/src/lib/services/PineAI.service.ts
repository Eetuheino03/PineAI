import { Injectable, Optional } from '@angular/core';
import { ApiService } from './api.service';
import {
    ActivityEntry,
    AssuranceProfile,
    Assessment,
    BaselineVersion,
    CapabilitySummary,
    ConsensusBaselinePreview,
    EvidenceBundle,
    Finding,
    FrontendError,
    InventoryImportPreview,
    InventoryItem,
    MeasurementContext,
    MeasurementProfile,
    PanelErrorMap,
    PineAISettings,
    ReconScan,
    ReconStatus,
    ReportScope,
    ReportScopePreview,
    ResultTaxonomy
} from '../models';
import { WorkflowFacade } from './workflow.facade';

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
    platformCapabilities: any = null;
    measurementProfiles: MeasurementProfile[] = [];
    selectedMeasurementProfile: MeasurementProfile = null;
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
    reportScopePreview: ReportScopePreview = null;
    consensusPreview: ConsensusBaselinePreview = null;
    assuranceProfile: AssuranceProfile = null;
    assuranceProfileVersions: AssuranceProfile[] = [];
    inventoryPreview: InventoryImportPreview = null;
    evidenceBundles: {[key: string]: EvidenceBundle} = {};
    evidenceBundleOrder: string[] = [];
    activity: ActivityEntry[] = [];
    panelErrors: PanelErrorMap = {};

    private measurementProfilesPromise: Promise<any> | null = null;
    private reconPromise: Promise<any> | null = null;
    private cachedCapabilitySummary: CapabilitySummary | null = null;
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

    workflow: WorkflowFacade;

    constructor(
        private api: ApiService,
        @Optional() workflow?: WorkflowFacade
    ) {
        this.workflow = workflow || new WorkflowFacade();
    }

    private module<T>(action: string, values: any = {}): Promise<T> {
        return this.api.moduleRequest<T>(
            Object.assign({module: 'PineAI', action}, values)
        );
    }

    private actionName(capability: string, fallback: string): string {
        const actions = this.capabilities && this.capabilities.actions;
        if (actions && !Array.isArray(actions) &&
            typeof actions[capability] === 'string') {
            return actions[capability];
        }
        return fallback;
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
            // Bootstrap Phase: fetch health, settings, platform capabilities, and assessments.
            await this.refreshHealth();
            await Promise.all([
                this.settle('settings', () => this.refreshSettings()),
                this.settle('capabilities', () => this.refreshPlatformOnlyCapabilities()),
                this.settle('assessments', () => this.refreshAssessments())
            ]);
            this.initialized = true;
            this.log(
                'success',
                'PineAI ready',
                'Baseline & Drift is available. Optional services load on demand.'
            );
        } catch (error) {
            const failure = this.error(error);
            this.log('error', 'Backend initialization failed', `${failure.code}: ${failure.message}`);
            throw error;
        } finally {
            this.initializing = false;
        }
    }

    async refreshPlatformOnlyCapabilities(): Promise<any> {
        this.platformCapabilities = await this.module<any>('platform_capabilities').catch(() => null);
        this.updateCapabilitySummary();
        return this.platformCapabilities;
    }

    async ensureMeasurementProfilesLoaded(): Promise<void> {
        if (this.measurementProfiles && this.measurementProfiles.length > 0) {
            return;
        }
        if (!this.measurementProfilesPromise) {
            this.measurementProfilesPromise = this.settle('measurement_profiles', () =>
                this.refreshMeasurementProfiles()
            ).finally(() => {
                this.measurementProfilesPromise = null;
            });
        }
        return this.measurementProfilesPromise;
    }

    async ensureReconLoaded(): Promise<void> {
        if (this.scans && this.scans.length > 0) {
            return;
        }
        if (!this.reconPromise) {
            this.reconPromise = this.settle('recon', async () => {
                await Promise.all([this.refreshReconStatus(), this.refreshScans()]);
            }).finally(() => {
                this.reconPromise = null;
            });
        }
        return this.reconPromise;
    }

    async refreshHealth(): Promise<any> {
        this.health = await this.module<any>('health');
        this.updateCapabilitySummary();
        return this.health;
    }

    async refreshSettings(): Promise<PineAISettings> {
        const result = await this.module<PineAISettings>('get_settings');
        this.settings = Object.assign({}, this.settings, result || {});
        return this.settings;
    }

    async refreshCapabilities(): Promise<any> {
        const platformPromise = this.module<any>('platform_capabilities')
            .catch(() => null);
        const assurancePromise = this.module<any>('assurance_capabilities')
            .catch(() => null);
        const values = await Promise.all([
            platformPromise,
            assurancePromise
        ]);
        this.platformCapabilities = values[0];
        this.capabilities = values[1] || values[0];
        this.updateCapabilitySummary();
        if (!this.capabilities && !this.platformCapabilities) {
            throw {
                code: 'capabilities_unavailable',
                message: 'Platform and assurance capabilities are unavailable.'
            };
        }
        return this.capabilities;
    }

    updateCapabilitySummary(): CapabilitySummary {
        this.cachedCapabilitySummary = this.computeCapabilitySummary();
        return this.cachedCapabilitySummary;
    }

    capabilitySummary(): CapabilitySummary {
        if (!this.cachedCapabilitySummary) {
            this.updateCapabilitySummary();
        }
        return this.cachedCapabilitySummary;
    }

    private computeCapabilitySummary(): CapabilitySummary {
        if (!this.health) {
            return {
                level: 'blocked',
                title: 'Core backend unavailable',
                detail: 'Guided and Expert modes require the PineAI module backend.',
                unavailable: ['backend']
            };
        }
        const platform = this.platformCapabilities || this.capabilities;
        const platformLevel = platform && platform.status;
        if (platformLevel === 'blocked') {
            const blocking = platform.blocking_codes || [];
            return {
                level: 'blocked',
                title: 'Platform capability blocked',
                detail: 'Resolve the local identity or storage capability before authoritative work.',
                unavailable: blocking
            };
        }
        const unavailable = Object.keys(this.panelErrors);
        if (platformLevel === 'degraded') {
            (platform.warnings || []).forEach((warning: string) => {
                if (unavailable.indexOf(warning) === -1) {
                    unavailable.push(warning);
                }
            });
        }
        if (unavailable.length > 0) {
            return {
                level: 'degraded',
                title: 'Degraded but usable',
                detail: 'Offline analysis remains available where its dependencies are ready.',
                unavailable
            };
        }
        return {
            level: 'ready',
            title: 'Ready for deterministic assurance',
            detail: 'Core backend, saved Recon access and local state are available.',
            unavailable: []
        };
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

    async refreshMeasurementProfiles(
        includeArchived: boolean = false
    ): Promise<MeasurementProfile[]> {
        const result: any = await this.module<any>(
            this.actionName(
                'list_measurement_profiles',
                'list_measurement_profiles'
            ),
            {include_archived: includeArchived}
        );
        const values = Array.isArray(result)
            ? result
            : result && Array.isArray(result.measurement_profiles)
                ? result.measurement_profiles
                : result && Array.isArray(result.profiles)
                    ? result.profiles : [];
        this.measurementProfiles = values.map(
            (value) => this.normalizeMeasurementProfile(value)
        );
        if (this.selectedMeasurementProfile) {
            const selectedId = this.measurementProfileId(
                this.selectedMeasurementProfile
            );
            this.selectedMeasurementProfile = this.measurementProfiles.find(
                (profile) => this.measurementProfileId(profile) === selectedId
            ) || null;
        }
        this.clearPanelError('measurement_profiles');
        return this.measurementProfiles;
    }

    measurementProfileId(profile: MeasurementProfile): string {
        return profile
            ? profile.measurement_profile_id || profile.profile_id || ''
            : '';
    }

    private normalizeMeasurementProfile(value: any): MeasurementProfile {
        const version = value && value.active_version
            ? value.active_version : {};
        const profile = version.profile || value.profile || value || {};
        return {
            measurement_profile_id:
                value.measurement_profile_id ||
                version.measurement_profile_id ||
                profile.measurement_profile_id || '',
            profile_id: value.profile_id,
            version_id:
                value.active_version_id ||
                version.version_id ||
                value.version_id,
            revision: value.revision || version.revision || 1,
            name: profile.name || value.name || '',
            description: profile.description || value.description || '',
            status: value.status || 'active',
            is_default: !!profile.is_default,
            context: {
                location_id: profile.location_id || '',
                measurement_point_id: profile.measurement_point_id || '',
                scan_profile_id: profile.scan_profile_id || '',
                radio_profile_id: profile.radio_profile_id || '',
                interface: profile.interface || '',
                declared_channels:
                    (profile.declared_channels || []).slice(),
                declared_bands:
                    (profile.declared_bands || []).slice(),
                scan_time: profile.scan_time,
                five_ghz_operator_confirmed:
                    !!profile.five_ghz_operator_confirmed
            } as any,
            created_at: value.created_at || version.created_at,
            updated_at: value.updated_at,
            digest: version.digest || value.digest
        } as any;
    }

    private measurementProfilePayload(value: any): any {
        const context = value.context || {};
        const channels = (context.declared_channels || []).slice();
        const bands = (context.declared_bands || []).slice();
        if (!bands.length) {
            if (channels.some((channel: number) => channel <= 14)) {
                bands.push('2.4');
            }
            if (channels.some((channel: number) => channel > 14)) {
                bands.push('5');
            }
        }
        return {
            name: value.name || '',
            description: value.description || '',
            location_id: context.location_id || '',
            measurement_point_id: context.measurement_point_id || '',
            scan_profile_id: context.scan_profile_id || '',
            radio_profile_id: context.radio_profile_id || '',
            interface: context.interface || '',
            declared_bands: bands,
            declared_channels: channels,
            scan_time: context.scan_time || 180,
            is_default: !!value.is_default,
            five_ghz_operator_confirmed:
                !!context.five_ghz_operator_confirmed
        };
    }

    async createMeasurementProfile(value: {
        name: string;
        description?: string;
        is_default?: boolean;
        context: MeasurementContext;
    }): Promise<MeasurementProfile> {
        const result: any = await this.module<any>(
            this.actionName(
                'create_measurement_profile',
                'create_measurement_profile'
            ),
            {profile: this.measurementProfilePayload(value)}
        );
        const profile = this.normalizeMeasurementProfile(
            result && result.measurement_profile
                ? result.measurement_profile
                : result && result.profile ? result.profile : result
        );
        await this.refreshMeasurementProfiles();
        this.applyMeasurementProfile(profile);
        this.log('success', 'Measurement profile created', profile.name || '');
        return profile;
    }

    async updateMeasurementProfile(
        profile: MeasurementProfile,
        changes: any
    ): Promise<MeasurementProfile> {
        const result: any = await this.module<any>(
            this.actionName(
                'update_measurement_profile',
                'update_measurement_profile'
            ),
            {
                measurement_profile_id: this.measurementProfileId(profile),
                expected_revision: profile.revision,
                changes: this.measurementProfilePayload(changes)
            }
        );
        const updated = this.normalizeMeasurementProfile(
            result && result.measurement_profile
                ? result.measurement_profile
                : result && result.profile ? result.profile : result
        );
        await this.refreshMeasurementProfiles();
        if (this.selectedMeasurementProfile &&
            this.measurementProfileId(this.selectedMeasurementProfile) ===
            this.measurementProfileId(profile)) {
            this.applyMeasurementProfile(updated);
        }
        this.log('success', 'Measurement profile updated', updated.name || '');
        return updated;
    }

    async archiveMeasurementProfile(
        profile: MeasurementProfile
    ): Promise<void> {
        await this.module<any>(
            this.actionName(
                'archive_measurement_profile',
                'archive_measurement_profile'
            ),
            {
                measurement_profile_id: this.measurementProfileId(profile),
                expected_revision: profile.revision
            }
        );
        if (this.selectedMeasurementProfile &&
            this.measurementProfileId(this.selectedMeasurementProfile) ===
            this.measurementProfileId(profile)) {
            this.applyMeasurementProfile(null);
        }
        await this.refreshMeasurementProfiles();
        this.log('warning', 'Measurement profile archived', profile.name || '');
    }

    applyMeasurementProfile(profile: MeasurementProfile | null): void {
        this.selectedMeasurementProfile = profile;
        if (!profile) {
            this.workflow.selectMeasurementProfile(null);
            return;
        }
        const source = profile.context || {} as MeasurementContext;
        this.measurementContext = {
            location_id: source.location_id || '',
            measurement_point_id: source.measurement_point_id || '',
            scan_profile_id: source.scan_profile_id || '',
            radio_profile_id: source.radio_profile_id || '',
            interface: source.interface || '',
            declared_channels: (source.declared_channels || []).slice(),
            declared_bands: (source.declared_bands || []).slice(),
            scan_time: source.scan_time || 180,
            five_ghz_operator_confirmed:
                !!source.five_ghz_operator_confirmed,
            measurement_profile_id: this.measurementProfileId(profile),
            measurement_profile_version_id:
                profile.version_id || null,
            measurement_profile_revision: profile.revision,
            measurement_profile_digest: profile.digest || null
        };
        this.workflow.selectMeasurementProfile(profile);
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

    async fetchWorkflowScan(scan: ReconScan): Promise<any> {
        try {
            const data = await this.api.nativeGet<any>(
                `/api/recon/scans/${encodeURIComponent(String(scan.scan_id))}`
            );
            this.workflow.rememberRawScan(scan, data);
            return data;
        } catch (error) {
            this.workflow.markScanError(scan, this.error(error));
            throw error;
        }
    }

    useWorkflowScan(scanId: string): void {
        const selection = this.workflow.snapshot.selected_scans.find(
            (value) => value.scan_id === scanId
        );
        const data = this.workflow.rawScan(scanId);
        if (!selection || !data) {
            throw {
                code: 'scan_required',
                message: 'Load the selected saved Recon scan first.'
            };
        }
        this.selectedScan = selection.scan;
        this.selectedScanData = data;
        this.resolvedScan = null;
        this.comparison = null;
        this.analysis = null;
        this.aiPreview = null;
        this.aiAnalysis = null;
        this.report = null;
        this.reportScopePreview = null;
        const profile = this.selectedMeasurementProfile;
        if (profile) {
            this.applyMeasurementProfile(profile);
        }
        const scanIdStr = String(selection.scan.scan_id);
        this.measurementContextByScan[scanIdStr] = Object.assign(
            {},
            this.measurementContext,
            {
                declared_channels:
                    (this.measurementContext.declared_channels || []).slice()
            }
        );
        this.measurementContext = this.measurementContextByScan[scanIdStr];
    }

    async loadScan(scan: ReconScan): Promise<any> {
        this.selectedScan = scan;
        this.selectedScanData = await this.fetchWorkflowScan(scan);
        this.resolvedScan = null;
        this.comparison = null;
        this.analysis = null;
        this.aiPreview = null;
        this.aiAnalysis = null;
        this.report = null;
        this.reportScopePreview = null;
        const scanIdStr = String(scan.scan_id);
        if (!this.measurementContextByScan[scanIdStr]) {
            const current = this.selectedMeasurementProfile
                ? this.measurementContext : {
                    location_id: '',
                    measurement_point_id: '',
                    scan_profile_id: '',
                    radio_profile_id: '',
                    interface: '',
                    declared_channels: []
                };
            this.measurementContextByScan[scanIdStr] = Object.assign(
                {},
                current,
                {
                    declared_channels:
                        (current.declared_channels || []).slice()
                }
            );
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
        return this.scanMetadataFor(
            this.selectedScan || {} as ReconScan,
            overrideContext || this.measurementContext
        );
    }

    scanMetadataFor(
        scan: ReconScan,
        context?: MeasurementContext
    ): any {
        const source: any = scan || {};
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
        const ctx = context;
        if (ctx) {
            const mc: any = {};
            if (ctx.location_id) mc.location_id = ctx.location_id;
            if (ctx.measurement_point_id) mc.measurement_point_id = ctx.measurement_point_id;
            if (ctx.scan_profile_id) mc.scan_profile_id = ctx.scan_profile_id;
            if (ctx.radio_profile_id) mc.radio_profile_id = ctx.radio_profile_id;
            if (ctx.interface) mc.interface = ctx.interface;
            if (ctx.declared_channels && ctx.declared_channels.length > 0) {
                mc.declared_channels = ctx.declared_channels.slice();
            }
            if (ctx.declared_bands && ctx.declared_bands.length > 0) {
                mc.declared_bands = ctx.declared_bands.slice();
            }
            if (ctx.measurement_profile_id) {
                mc.measurement_profile_id = ctx.measurement_profile_id;
            }
            if (ctx.measurement_profile_version_id) {
                mc.measurement_profile_version_id =
                    ctx.measurement_profile_version_id;
            }
            if (ctx.measurement_profile_revision !== undefined &&
                ctx.measurement_profile_revision !== null) {
                mc.measurement_profile_revision =
                    ctx.measurement_profile_revision;
            }
            if (ctx.measurement_profile_digest) {
                mc.measurement_profile_digest =
                    ctx.measurement_profile_digest;
            }
            if (Object.keys(mc).length > 0) {
                result.measurement_context = mc;
            }
            if ((result.scan_time === undefined ||
                result.scan_time === null) &&
                ctx.scan_time !== undefined &&
                ctx.scan_time !== null) {
                result.scan_time = ctx.scan_time;
            }
        }
        return result;
    }

    reasonLabel(reason: string, lang: 'en' | 'fi' = 'fi'): string {
        const fiMap: {[key: string]: string} = {
            legacy_baseline_missing_measurement_context: 'Vanha baseline ilman mittaustietoja',
            measurement_context_unknown: 'Mittaustiedot puuttuvat tai ne ovat tuntemattomat (location_id / measurement_point_id)',
            location_mismatch: 'Sijainti (location_id) ei täsmää baselineen',
            measurement_point_mismatch: 'Mittauspiste (measurement_point_id) ei täsmää baselineen',
            radio_profile_mismatch: 'Radio/rauta-profiili ei täsmää baselineen',
            radio_profile_unknown: 'Radio-ohjaimen profiili on tuntematon',
            interface_mismatch: 'Radio/rauta-rajapinta ei täsmää baselineen',
            interface_unknown: 'Radio/rauta-rajapinta on tuntematon',
            scan_profile_mismatch: 'Skannausprofiili poikkeaa baselinesta',
            scan_profile_unknown: 'Skannausprofiili on tuntematon',
            channel_coverage_unknown: 'Kanavakattavuus on tuntematon (ilmoittamaton kanalista)',
            declared_channels_do_not_cover_baseline_channels: 'Määritellyt kanavat eivät kata baselinen kanavia',
            current_scan_contains_no_access_points: 'Nykyisessä skannauksessa ei havaittu yhtään tukiasemaa',
            current_scan_does_not_cover_baseline_bands: 'Skannaus ei kata baselinen taajuusalueita',
            band_coverage_is_incomplete: 'Taajuusalueen kattavuus on puutteellinen',
            scan_duration_is_unknown: 'Skannauksen kesto on tuntematon',
            current_scan_is_materially_shorter: 'Skannauksen kesto on huomattavasti baselinea lyhyempi',
            low_comparison_quality_score: 'Vertailun laatupistemäärä on liian alhainen (< 75%)',
            low_overall_comparison_quality_score: 'Vertailun kokonaislaatu on liian alhainen (< 75%)',
            low_baseline_ap_detection_ratio: 'Ankkuri-tukiasemien havaintosuhde liian alhainen (< 50%)',
            baseline_ap_detection_ratio_too_low: 'Baselinen ankkuri-tukiasemien havaintosuhde liian alhainen (< 50%)',
            signal_profile_changed_materially: 'Signaaliprofiilissa merkittävä muutos (> 15 dB)',
            essential_measurement_context_missing: 'Mittaustietoja tai puuttuvia kanavia ei voida vahvistaa'
        };
        const enMap: {[key: string]: string} = {
            legacy_baseline_missing_measurement_context: 'Legacy baseline without measurement context',
            measurement_context_unknown: 'Measurement context missing or unknown (location_id / measurement_point_id)',
            location_mismatch: 'Location ID does not match baseline',
            measurement_point_mismatch: 'Measurement point ID does not match baseline',
            radio_profile_mismatch: 'Radio profile does not match baseline',
            radio_profile_unknown: 'Radio profile is unknown',
            interface_mismatch: 'Radio/interface does not match baseline',
            interface_unknown: 'Radio/interface is unknown',
            scan_profile_mismatch: 'Scan profile differs from baseline',
            scan_profile_unknown: 'Scan profile is unknown',
            channel_coverage_unknown: 'Channel coverage is unknown (undeclared channels)',
            declared_channels_do_not_cover_baseline_channels: 'Declared channels do not cover candidate channels',
            current_scan_contains_no_access_points: 'Current scan contains no access points',
            current_scan_does_not_cover_baseline_bands: 'Current scan does not cover baseline frequency bands',
            band_coverage_is_incomplete: 'Band coverage is incomplete',
            scan_duration_is_unknown: 'Scan duration is unknown',
            current_scan_is_materially_shorter: 'Scan duration is materially shorter than baseline',
            low_comparison_quality_score: 'Comparison quality score is too low (< 75%)',
            low_overall_comparison_quality_score: 'Overall comparison quality score is too low (< 75%)',
            low_baseline_ap_detection_ratio: 'Baseline anchor AP detection ratio is too low (< 50%)',
            baseline_ap_detection_ratio_too_low: 'Baseline anchor AP detection ratio is too low (< 50%)',
            signal_profile_changed_materially: 'Signal profile has changed materially (> 15 dB)',
            essential_measurement_context_missing: 'Essential measurement context missing'
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
        const previousAssessmentId = this.activeAssessment
            ? this.activeAssessment.assessment_id : '';
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
        if (previousAssessmentId !== assessmentId) {
            this.selectedScan = null;
            this.selectedScanData = null;
            this.resolvedScan = null;
            this.assuranceProfile = null;
            this.assuranceProfileVersions = [];
            this.inventoryPreview = null;
            this.consensusPreview = null;
            this.evidenceBundles = {};
            this.evidenceBundleOrder = [];
            this.reportScopePreview = null;
        }
        if (!preserveWorkflow) {
            this.comparison = null;
            this.analysis = null;
            this.aiPreview = null;
            this.aiAnalysis = null;
            this.report = null;
        }
        await Promise.all([
            this.settle('baselines', () => this.refreshBaselines()),
            this.settle('findings', () => this.refreshFindings()),
            this.settle(
                'assurance_profile',
                () => this.refreshAssuranceProfile()
            )
        ]);
        this.workflow.setAssessment(
            this.activeAssessment,
            this.activeBaselineId()
        );
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
        const created = result && result.assessment
            ? result.assessment : result;
        await this.refreshAssessments();
        await this.selectAssessment(created.assessment_id);
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
            this.reportScopePreview = null;
            this.reportScopePreview = null;
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
            this.selectedScan = null;
            this.selectedScanData = null;
            this.resolvedScan = null;
            this.baselines = [];
            this.activeBaselineVersion = null;
            this.findings = [];
            this.comparison = null;
            this.analysis = null;
            this.aiPreview = null;
            this.aiAnalysis = null;
            this.report = null;
            this.reportScopePreview = null;
            this.consensusPreview = null;
            this.assuranceProfile = null;
            this.inventoryPreview = null;
            this.evidenceBundles = {};
            this.evidenceBundleOrder = [];
            this.workflow.setAssessment(null);
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

    consensusPolicyId(): string {
        const consensus = this.capabilities && (
            this.capabilities.consensus ||
            this.capabilities.consensus_baseline
        );
        return consensus && (
            consensus.default_policy_id ||
            consensus.consensus_policy_id
        ) || 'strict_80_v1';
    }

    private workflowObservations(): any[] {
        const selected = this.workflow.selectedRawScans();
        if (selected.length < 2 || selected.length > 5) {
            throw {
                code: 'consensus_scan_count',
                message: 'Select between two and five loaded Recon scans.'
            };
        }
        return selected.map((value) => ({
            scan: value.data,
            scan_metadata: this.scanMetadataFor(
                value.scan,
                this.measurementContext
            )
        }));
    }

    async previewConsensusBaseline(
        maxSourceAgeHours: number = 24
    ): Promise<ConsensusBaselinePreview> {
        this.requireAssessment();
        this.consensusPreview = await this.module<ConsensusBaselinePreview>(
            'preview_consensus_baseline',
            {
                assessment_id: this.activeAssessment.assessment_id,
                observations: this.workflowObservations(),
                max_source_age_hours: maxSourceAgeHours
            }
        );
        const digest = this.consensusPreview
            ? this.consensusPreview.preview_digest ||
              this.consensusPreview.consensus_digest ||
              (this.consensusPreview.baseline_model &&
                  this.consensusPreview.baseline_model
                      .baseline_model_digest) || ''
            : '';
        this.workflow.setConsensusPreview(digest);
        this.clearPanelError('baselines');
        this.log(
            'success',
            'Consensus preview ready',
            `${this.workflow.snapshot.selected_scans.length} scans evaluated.`
        );
        return this.consensusPreview;
    }

    async createConsensusBaselineVersion(
        label: string,
        maxSourceAgeHours: number = 24
    ): Promise<any> {
        this.requireAssessment();
        if (!this.consensusPreview) {
            throw {
                code: 'consensus_preview_required',
                message: 'Preview the deterministic consensus before creating a version.'
            };
        }
        const assessmentId = this.activeAssessment.assessment_id;
        const result: any = await this.module<any>(
            'create_consensus_baseline_version',
            {
                assessment_id: assessmentId,
                expected_revision: this.activeAssessment.revision,
                observations: this.workflowObservations(),
                label: label || '',
                max_source_age_hours: maxSourceAgeHours
            }
        );
        this.consensusPreview = null;
        this.workflow.setConsensusPreview('');
        await this.selectAssessment(assessmentId, true);
        this.log(
            'success',
            'Consensus baseline version created',
            label || 'Immutable candidate saved.'
        );
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
        this.workflow.setBaselineVersion(baselineVersionId);
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
        const comparisonValue = this.comparison || {};
        this.workflow.setComparison(
            comparisonValue.comparison_id ||
            comparisonValue.analysis_id ||
            comparisonValue.snapshot_id || '',
            true,
            false
        );
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
            const comparisonValue = this.comparison || {};
            this.workflow.setComparison(
                comparisonValue.comparison_id ||
                comparisonValue.analysis_id ||
                comparisonValue.snapshot_id || '',
                true,
                true
            );
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

    assuranceProfileId(profile: AssuranceProfile): string {
        return profile
            ? (profile as any).assurance_profile_version_id ||
              profile.assurance_profile_id ||
              profile.profile_id || ''
            : '';
    }

    async refreshAssuranceProfile(): Promise<AssuranceProfile> {
        this.requireAssessment();
        const result: any = await this.module<any>(
            'list_assurance_profile_versions',
            {assessment_id: this.activeAssessment.assessment_id}
        );
        this.assuranceProfileVersions = Array.isArray(result)
            ? result
            : result && Array.isArray(result.assurance_profile_versions)
                ? result.assurance_profile_versions
                : result && Array.isArray(result.assurance_profiles)
                    ? result.assurance_profiles
                : result && Array.isArray(result.profiles)
                    ? result.profiles : [];
        let active: any = result && (
            result.active_assurance_profile_version ||
            result.active_profile
        );
        if (typeof active === 'string') {
            const detail: any = await this.module<any>(
                'get_assurance_profile_version',
                {
                    assessment_id: this.activeAssessment.assessment_id,
                    assurance_profile_version_id: active
                }
            );
            active = detail && (
                detail.assurance_profile ||
                detail.assurance_profile_version ||
                detail.profile
            ) || detail;
        }
        if (!active) {
            active = this.assuranceProfileVersions.find(
                (profile) => !!profile.active ||
                    profile.status === 'active'
            ) || null;
        }
        this.assuranceProfile = active;
        this.workflow.setAssuranceProfileRevision(
            active && typeof active.revision === 'number'
                ? active.revision
                : active && typeof active.version === 'number'
                    ? active.version : null
        );
        this.clearPanelError('assurance_profile');
        return this.assuranceProfile;
    }

    async previewInventoryCsv(content: string): Promise<InventoryImportPreview> {
        if (!content || !content.trim()) {
            throw {
                code: 'inventory_csv_required',
                message: 'Paste or select a CSV inventory first.'
            };
        }
        this.inventoryPreview = await this.module<InventoryImportPreview>(
            'preview_inventory_csv',
            {content}
        );
        this.clearPanelError('assurance_profile');
        return this.inventoryPreview;
    }

    async createAssuranceProfileVersion(
        label: string,
        coverageMode: 'partial' | 'authoritative' = 'partial'
    ): Promise<any> {
        this.requireAssessment();
        if (!this.inventoryPreview ||
            (this.inventoryPreview.errors || []).length > 0) {
            throw {
                code: 'inventory_preview_required',
                message: 'Create a valid inventory preview first.'
            };
        }
        const assessmentId = this.activeAssessment.assessment_id;
        const result = await this.module<any>(
            'create_assurance_profile_version',
            {
                assessment_id: assessmentId,
                expected_revision: this.activeAssessment.revision,
                label: label || '',
                inventory_preview: this.inventoryPreview,
                coverage_mode: coverageMode
            }
        );
        this.inventoryPreview = null;
        await this.selectAssessment(assessmentId, true);
        this.log(
            'success',
            'Assurance profile version created',
            label || 'Inventory and policy saved.'
        );
        return result;
    }

    async activateAssuranceProfileVersion(
        profile: AssuranceProfile
    ): Promise<any> {
        this.requireAssessment();
        const id = this.assuranceProfileId(profile);
        if (!id) {
            throw {
                code: 'assurance_profile_required',
                message: 'Select a valid assurance profile version.'
            };
        }
        const assessmentId = this.activeAssessment.assessment_id;
        const result = await this.module<any>(
            'activate_assurance_profile_version',
            {
                assessment_id: assessmentId,
                expected_revision: this.activeAssessment.revision,
                assurance_profile_version_id: id,
                authoritative_confirmation: true
            }
        );
        await this.selectAssessment(assessmentId, true);
        this.log('success', 'Assurance profile activated', id);
        return result;
    }

    async exportInventoryCsv(profile: AssuranceProfile): Promise<any> {
        this.requireAssessment();
        const result: any = await this.module<any>('export_inventory_csv', {
            assessment_id: this.activeAssessment.assessment_id,
            assurance_profile_version_id: this.assuranceProfileId(profile)
        });
        if (result) {
            this.downloadText(
                result.filename || 'pineai-inventory.csv',
                result.content || result.csv || '',
                'text/csv;charset=utf-8'
            );
        }
        return result;
    }

    async loadEvidenceBundle(
        findingId: string,
        comparisonId?: string
    ): Promise<EvidenceBundle> {
        this.requireAssessment();
        const resolvedComparisonId = comparisonId || this.comparisonId();
        const key = [
            this.activeAssessment.assessment_id,
            resolvedComparisonId,
            findingId
        ].join(':');
        if (this.evidenceBundles[key]) {
            return this.evidenceBundles[key];
        }
        const result: any = await this.module<any>('get_evidence_bundle', {
            assessment_id: this.activeAssessment.assessment_id,
            comparison_id: resolvedComparisonId,
            item_id: findingId
        });
        const source = result && result.evidence_bundle
            ? result.evidence_bundle : result;
        const bundle: EvidenceBundle =
            this.normalizeEvidenceBundle(source, findingId);
        this.evidenceBundles[key] = bundle;
        this.evidenceBundleOrder =
            this.evidenceBundleOrder.filter((value) => value !== key);
        this.evidenceBundleOrder.push(key);
        while (this.evidenceBundleOrder.length > 20) {
            const oldest = this.evidenceBundleOrder.shift();
            if (oldest) {
                delete this.evidenceBundles[oldest];
            }
        }
        return bundle;
    }

    private normalizeEvidenceBundle(
        value: any,
        itemId: string
    ): EvidenceBundle {
        if (value && Array.isArray(value.pairs)) {
            return value;
        }
        const beforeAfter = value && value.before_after
            ? value.before_after : {};
        const before = beforeAfter.before;
        const after = beforeAfter.after;
        const beforeObject = before && typeof before === 'object' &&
            !Array.isArray(before) ? before : null;
        const afterObject = after && typeof after === 'object' &&
            !Array.isArray(after) ? after : null;
        let fields: string[] = [];
        if (beforeObject || afterObject) {
            fields = Object.keys(beforeObject || {})
                .concat(Object.keys(afterObject || {}))
                .filter((field, index, all) => all.indexOf(field) === index)
                .sort();
        }
        if (!fields.length) {
            fields = ['value'];
        }
        const subjectId = value && value.item
            ? value.item.subject_id : undefined;
        const pairs = fields.map((field) => {
            const beforeValue = field === 'value' && !beforeObject
                ? before : beforeObject ? beforeObject[field] : undefined;
            const afterValue = field === 'value' && !afterObject
                ? after : afterObject ? afterObject[field] : undefined;
            return {
                field,
                change_type: value && value.item
                    ? value.item.change_type ||
                      value.item.rule_id ||
                      value.item_type
                    : value && value.item_type,
                before: beforeValue === undefined ? null : {
                    subject_id: subjectId,
                    value: beforeValue
                },
                after: afterValue === undefined ? null : {
                    subject_id: subjectId,
                    value: afterValue
                }
            };
        });
        return Object.assign({}, value || {}, {
            finding_id: itemId,
            pairs
        });
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

    defaultReportScope(): ReportScope {
        return {
            type: 'comparison',
            comparison_id: this.hasComparison() ? this.comparisonId() : '',
            finding_mode: 'comparison',
            statuses: ['open', 'acknowledged', 'resolved'],
            severities: [],
            rule_ids: [],
            subject_ids: [],
            include_evidence: true,
            include_inventory_policy: true,
            include_ai: false
        };
    }

    async prepareReportScope(
        scope: ReportScope,
        privacyProfile: 'local_full' | 'share_safe'
    ): Promise<ReportScopePreview> {
        this.requireAssessment();
        this.reportScopePreview = await this.module<ReportScopePreview>(
            'prepare_report',
            {
                assessment_id: this.activeAssessment.assessment_id,
                scope,
                privacy_profile: privacyProfile
            }
        );
        if (!this.reportScopePreview ||
            !this.reportScopePreview.scope_digest) {
            throw {
                code: 'invalid_report_preview',
                message: 'The backend did not return an authoritative scope digest.'
            };
        }
        this.workflow.setReportScopeDigest(
            this.reportScopePreview.scope_digest
        );
        this.clearPanelError('reports');
        return this.reportScopePreview;
    }

    async generateReport(
        format: 'json' | 'html',
        includeAi: boolean,
        scope?: ReportScope,
        privacyProfile: 'local_full' | 'share_safe' = 'local_full'
    ): Promise<any> {
        this.requireAssessment();
        const selectedScope = scope || this.defaultReportScope();
        if (!this.reportScopePreview ||
            !this.reportScopePreview.scope_digest) {
            throw {
                code: 'report_scope_preview_required',
                message: 'Prepare and review the report scope before generation.'
            };
        }
        this.report = await this.module<any>('generate_report', {
            assessment_id: this.activeAssessment.assessment_id,
            scope: selectedScope,
            privacy_profile: privacyProfile,
            format,
            scope_digest: this.reportScopePreview.scope_digest,
            ai_analysis: includeAi ? this.aiAnalysisValue() : null
        });
        this.clearPanelError('reports');
        this.log('success', `${format.toUpperCase()} report generated`, this.report.filename || '');
        return this.report;
    }

    availableComparisons(): any[] {
        const values = this.activeAssessment &&
            Array.isArray(this.activeAssessment.comparisons)
            ? this.activeAssessment.comparisons.slice() : [];
        const current = this.analysis && this.analysis.comparison
            ? this.analysis.comparison : this.comparison;
        if (current) {
            const currentId = current.comparison_id ||
                current.analysis_id || current.snapshot_id;
            if (currentId && !values.some((value) =>
                (value.comparison_id || value.analysis_id ||
                    value.snapshot_id) === currentId
            )) {
                values.unshift(current);
            }
        }
        return values;
    }

    resultTaxonomy(value?: any): ResultTaxonomy {
        const source = value || (
            this.analysis && this.analysis.comparison
                ? this.analysis.comparison
                : this.comparison
        ) || {};
        const provided = source.result_taxonomy || source.taxonomy;
        if (provided) {
            return {
                observed_changes:
                    provided.observed_changes || provided.changes || [],
                deviations: provided.deviations || [],
                security_findings:
                    provided.security_findings || provided.findings || []
            };
        }
        const findings = source.candidate_findings || [];
        const result: ResultTaxonomy = {
            observed_changes: [],
            deviations: [],
            security_findings: []
        };
        for (const finding of findings) {
            const category = finding.taxonomy || finding.category ||
                finding.result_type || '';
            if (category === 'observed_change' || category === 'change') {
                result.observed_changes.push(finding);
            } else if (category === 'deviation' ||
                category === 'policy_deviation') {
                result.deviations.push(finding);
            } else {
                result.security_findings.push(finding);
            }
        }
        return result;
    }

    async refreshObservedChanges(): Promise<any[]> {
        this.requireAssessment();
        const result: any = await this.module<any>('list_observed_changes', {
            assessment_id: this.activeAssessment.assessment_id,
            comparison_id: this.hasComparison() ? this.comparisonId() : null
        });
        return Array.isArray(result)
            ? result
            : result && Array.isArray(result.observed_changes)
                ? result.observed_changes : [];
    }

    downloadReport(result: any): void {
        if (!result) {
            return;
        }
        const filename = result.filename || 'pineai-report.json';
        const exportPath = result.export && (
            result.export.filename ||
            result.export.download &&
            result.export.download.body &&
            result.export.download.body.filename
        );
        if (exportPath) {
            this.api.APIDownload(exportPath, filename);
            return;
        }
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
        this.downloadText(filename, text, mime);
    }

    private downloadText(
        filename: string,
        text: string,
        mime: string
    ): void {
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
