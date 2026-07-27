import { Injectable } from '@angular/core';
import { ApiService } from './api.service';
import {
    ActivityEntry,
    PineAISettings,
    ReconScan,
    ReconStatus,
    SessionSnapshot,
    SupportedBand
} from '../models';

@Injectable({
    providedIn: 'root'
})
export class PineAIService {
    health: any = null;
    settings: PineAISettings = null;
    advisorCapabilities: any = null;
    adaptiveCapabilities: any = null;
    reconStatus: ReconStatus = null;
    scans: ReconScan[] = [];
    selectedScan: ReconScan = null;
    selectedScanData: any = null;
    profileResult: any = null;
    selectedTargetIds: string[] = [];
    engagements: any[] = [];
    activeEngagement: any = null;
    advisorResult: any = null;
    selectedPathIds: string[] = [];
    adaptivePlan: any = null;
    sessionHistory: SessionSnapshot[] = [];
    activity: ActivityEntry[] = [];
    initializing = false;
    initialized = false;

    constructor(private api: ApiService) {}

    private module<T>(action: string, values: any = {}): Promise<T> {
        return this.api.moduleRequest<T>(
            Object.assign({module: 'PineAI', action}, values)
        );
    }

    error(error: any): {code: string, message: string} {
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

    async initialize(): Promise<void> {
        if (this.initializing) {
            return;
        }
        this.initializing = true;
        try {
            await Promise.all([
                this.refreshHealth(),
                this.refreshSettings(),
                this.refreshCapabilities()
            ]);
            await Promise.all([
                this.refreshReconStatus(),
                this.refreshScans(),
                this.refreshEngagements()
            ]);
            this.initialized = true;
            this.log('success', 'PineAI ready', 'Backend and device state loaded.');
        } catch (error) {
            const failure = this.error(error);
            this.log('error', 'Initialization failed', `${failure.code}: ${failure.message}`);
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
        this.settings = await this.module<PineAISettings>('get_settings');
        return this.settings;
    }

    async refreshCapabilities(): Promise<void> {
        const values = await Promise.all([
            this.module<any>('advisor_capabilities'),
            this.module<any>('adaptive_recon_capabilities')
        ]);
        this.advisorCapabilities = values[0];
        this.adaptiveCapabilities = values[1];
    }

    async saveSettings(
        language: 'en' | 'fi',
        shareSsids: boolean,
        supportedBands: SupportedBand[]
    ): Promise<PineAISettings> {
        this.settings = await this.module<PineAISettings>('update_settings', {
            settings: {
                language,
                share_ssids: shareSsids,
                supported_bands: supportedBands
            }
        });
        this.log('success', 'Settings saved', 'Privacy and device capabilities updated.');
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
        await Promise.all([this.refreshSettings(), this.refreshHealth()]);
        this.log('success', 'OpenAI key stored', 'The key was stored on the Pineapple.');
    }

    async deleteApiKey(): Promise<void> {
        await this.module<any>('delete_openai_api_key');
        await Promise.all([this.refreshSettings(), this.refreshHealth()]);
        this.log('warning', 'Managed OpenAI key removed');
    }

    async refreshReconStatus(): Promise<ReconStatus> {
        this.reconStatus = await this.api.nativeGet<ReconStatus>('/api/recon/status');
        return this.reconStatus;
    }

    async refreshScans(): Promise<ReconScan[]> {
        const result: any = await this.api.nativeGet<any>('/api/recon/scans');
        this.scans = Array.isArray(result) ? result : [];
        this.scans.sort((left, right) => String(right.date).localeCompare(String(left.date)));
        return this.scans;
    }

    async loadScan(scan: ReconScan, preserveWorkflow: boolean = false): Promise<any> {
        this.selectedScan = scan;
        this.selectedScanData = await this.api.nativeGet<any>(
            `/api/recon/scans/${encodeURIComponent(String(scan.scan_id))}`
        );
        if (!preserveWorkflow) {
            this.profileResult = null;
            this.selectedTargetIds = [];
            this.advisorResult = null;
            this.selectedPathIds = [];
            this.adaptivePlan = null;
        }
        this.log('success', 'Recon scan loaded', `Scan ${scan.scan_id} is ready for profiling.`);
        return this.selectedScanData;
    }

    private options(aiEnabled: boolean = true): any {
        return {
            language: this.settings ? this.settings.language : 'en',
            share_ssids: this.settings ? this.settings.share_ssids : false,
            ai_enabled: aiEnabled
        };
    }

    async prepareProfile(): Promise<any> {
        this.requireSelectedScan();
        return this.module<any>('prepare_profile_recon', {
            scan: this.selectedScanData,
            scan_metadata: this.selectedScan,
            options: this.options(true)
        });
    }

    async profileSelectedScan(
        aiEnabled: boolean,
        preserveWorkflow: boolean = false
    ): Promise<any> {
        this.requireSelectedScan();
        this.profileResult = await this.module<any>('profile_recon', {
            scan: this.selectedScanData,
            scan_metadata: this.selectedScan,
            options: this.options(aiEnabled)
        });
        if (!preserveWorkflow) {
            this.selectedTargetIds = [];
            this.advisorResult = null;
            this.selectedPathIds = [];
            this.adaptivePlan = null;
        }
        const state = this.profileResult.ai_status
            ? this.profileResult.ai_status.state : 'unknown';
        this.log(
            state === 'complete' ? 'success' : 'warning',
            'Target profile generated',
            `AI status: ${state}.`
        );
        return this.profileResult;
    }

    private requireSelectedScan(): void {
        if (!this.selectedScan || !this.selectedScanData) {
            throw {code: 'scan_required', message: 'Select and load a Recon scan first.'};
        }
    }

    toggleTarget(targetId: string, selected: boolean): void {
        const values = this.selectedTargetIds.filter((value) => value !== targetId);
        if (selected && values.length < 10) {
            values.push(targetId);
        }
        this.selectedTargetIds = values;
    }

    async refreshEngagements(includeArchived: boolean = false): Promise<any[]> {
        const result: any = await this.module<any>('list_engagements', {
            include_archived: includeArchived
        });
        this.engagements = result && Array.isArray(result.engagements)
            ? result.engagements : [];
        return this.engagements;
    }

    async selectEngagement(
        engagementId: string,
        preserveWorkflow: boolean = false
    ): Promise<any> {
        this.activeEngagement = await this.module<any>('get_engagement', {
            engagement_id: engagementId,
            after_sequence: 0,
            limit: 100
        });
        if (!preserveWorkflow) {
            this.advisorResult = null;
            this.selectedPathIds = [];
            this.adaptivePlan = null;
        }
        return this.activeEngagement;
    }

    async createEngagement(value: any): Promise<any> {
        this.activeEngagement = await this.module<any>('create_engagement', {
            engagement: value
        });
        await this.refreshEngagements();
        this.log('success', 'Engagement created', this.activeEngagement.name);
        return this.activeEngagement;
    }

    async updateEngagement(changes: any): Promise<any> {
        if (!this.activeEngagement) {
            throw {code: 'engagement_required', message: 'Select an engagement first.'};
        }
        try {
            this.activeEngagement = await this.module<any>('update_engagement', {
                engagement_id: this.activeEngagement.engagement_id,
                expected_revision: this.activeEngagement.revision,
                changes
            });
            await this.refreshEngagements();
            this.log('success', 'Engagement updated', this.activeEngagement.name);
            return this.activeEngagement;
        } catch (error) {
            if (this.error(error).code === 'revision_conflict') {
                await this.selectEngagement(this.activeEngagement.engagement_id);
            }
            throw error;
        }
    }

    async archiveEngagement(): Promise<void> {
        if (!this.activeEngagement) {
            return;
        }
        await this.module<any>('archive_engagement', {
            engagement_id: this.activeEngagement.engagement_id,
            expected_revision: this.activeEngagement.revision
        });
        this.log('warning', 'Engagement archived', this.activeEngagement.name);
        this.activeEngagement = null;
        this.advisorResult = null;
        await this.refreshEngagements();
    }

    async appendEvent(event: any): Promise<any> {
        if (!this.activeEngagement) {
            throw {code: 'engagement_required', message: 'Select an engagement first.'};
        }
        const engagementId = this.activeEngagement.engagement_id;
        try {
            const result = await this.module<any>('append_engagement_event', {
                engagement_id: engagementId,
                expected_revision: this.activeEngagement.revision,
                event
            });
            await this.selectEngagement(engagementId, true);
            this.log('success', 'Engagement event recorded', event.event_type);
            return result;
        } catch (error) {
            if (this.error(error).code === 'revision_conflict') {
                await this.selectEngagement(engagementId, true);
            }
            throw error;
        }
    }

    async prepareAdvice(): Promise<any> {
        this.requireAdvisorInputs();
        return this.module<any>('prepare_attack_paths', {
            engagement_id: this.activeEngagement.engagement_id,
            profile_result: this.profileResult,
            target_ids: this.selectedTargetIds,
            options: this.options(true)
        });
    }

    async advise(aiEnabled: boolean): Promise<any> {
        this.requireAdvisorInputs();
        this.advisorResult = await this.module<any>('advise_attack_paths', {
            engagement_id: this.activeEngagement.engagement_id,
            profile_result: this.profileResult,
            target_ids: this.selectedTargetIds,
            options: this.options(aiEnabled)
        });
        await this.selectEngagement(this.activeEngagement.engagement_id, true);
        this.selectedPathIds = [];
        this.adaptivePlan = null;
        const state = this.advisorResult.advisor_status
            ? this.advisorResult.advisor_status.state : 'unknown';
        this.log(
            state === 'complete' ? 'success' : 'warning',
            'Attack paths generated',
            `Advisor status: ${state}.`
        );
        return this.advisorResult;
    }

    private requireAdvisorInputs(): void {
        if (!this.profileResult) {
            throw {code: 'profile_required', message: 'Profile a Recon scan first.'};
        }
        if (!this.activeEngagement) {
            throw {code: 'engagement_required', message: 'Select an engagement first.'};
        }
        if (!this.selectedTargetIds.length) {
            throw {code: 'targets_required', message: 'Select at least one target.'};
        }
    }

    pathSupportsAdaptive(path: any): boolean {
        return path && Array.isArray(path.steps) && path.steps.some(
            (step) => step.action_id === 'collect_additional_recon'
        );
    }

    togglePath(pathId: string, selected: boolean): void {
        const values = this.selectedPathIds.filter((value) => value !== pathId);
        if (selected) {
            values.push(pathId);
        }
        this.selectedPathIds = values;
    }

    deviceContext(): any {
        return {
            observed_at: new Date().toISOString(),
            supported_bands: this.settings ? this.settings.supported_bands : [],
            recon_status: this.reconStatus
        };
    }

    async prepareAdaptive(): Promise<any> {
        return this.adaptiveRequest('prepare_adaptive_recon');
    }

    async recommendAdaptive(): Promise<any> {
        const result = await this.adaptiveRequest('recommend_adaptive_recon');
        await this.selectEngagement(this.activeEngagement.engagement_id, true);
        this.adaptivePlan = result;
        this.log('success', 'Adaptive Recon plan recommended', result.plan_id);
        return result;
    }

    private async adaptiveRequest(action: string): Promise<any> {
        if (!this.advisorResult || !this.selectedPathIds.length) {
            throw {code: 'paths_required', message: 'Select Recon-capable advisor paths.'};
        }
        if (!this.settings || !this.settings.supported_bands.length) {
            throw {code: 'bands_required', message: 'Configure a device-confirmed band first.'};
        }
        await this.refreshReconStatus();
        return this.module<any>(action, {
            engagement_id: this.activeEngagement.engagement_id,
            expected_revision: this.activeEngagement.revision,
            profile_result: this.profileResult,
            advisor_result: this.advisorResult,
            selected_path_ids: this.selectedPathIds,
            history: this.sessionHistory,
            device_context: this.deviceContext(),
            options: this.options(true)
        });
    }

    async approveAndStartAdaptive(candidateId: string): Promise<any> {
        if (!this.adaptivePlan) {
            throw {code: 'plan_required', message: 'Recommend a plan first.'};
        }
        await this.refreshReconStatus();
        const approved: any = await this.module<any>('approve_recon_plan', {
            engagement_id: this.activeEngagement.engagement_id,
            expected_revision: this.activeEngagement.revision,
            plan_id: this.adaptivePlan.plan_id,
            candidate_id: candidateId,
            device_context: this.deviceContext()
        });
        await this.selectEngagement(this.activeEngagement.engagement_id, true);
        const descriptor = approved.rest_request;
        if (
            !descriptor ||
            descriptor.method !== 'POST' ||
            descriptor.path !== '/api/recon/start'
        ) {
            throw {code: 'invalid_rest_descriptor', message: 'Backend returned an unsafe Recon descriptor.'};
        }
        const startResponse: any = await this.api.nativePost<any>(
            descriptor.path, descriptor.body
        );
        const started = await this.module<any>('record_recon_scan_started', {
            engagement_id: this.activeEngagement.engagement_id,
            expected_revision: this.activeEngagement.revision,
            plan_id: this.adaptivePlan.plan_id,
            start_response: startResponse
        });
        await this.selectEngagement(this.activeEngagement.engagement_id, true);
        this.adaptivePlan = started;
        this.log('success', 'Adaptive Recon started', this.adaptivePlan.plan_id);
        return startResponse;
    }

    async finishAdaptive(
        outcome: 'completed' | 'failed' | 'aborted',
        scanId: number,
        profileResult: any = null,
        errorCode: string = null
    ): Promise<any> {
        const result = await this.module<any>('record_recon_scan_finished', {
            engagement_id: this.activeEngagement.engagement_id,
            expected_revision: this.activeEngagement.revision,
            plan_id: this.adaptivePlan.plan_id,
            outcome,
            scan_id: scanId,
            profile_result: profileResult,
            error_code: errorCode
        });
        await this.selectEngagement(this.activeEngagement.engagement_id, true);
        this.adaptivePlan = result;
        this.log(
            outcome === 'completed' ? 'success' : 'warning',
            `Adaptive Recon ${outcome}`,
            this.adaptivePlan.plan_id
        );
        return result;
    }

    addCurrentProfileToHistory(request: {scan_time: number, band: string}): void {
        if (!this.profileResult || !this.selectedScan) {
            return;
        }
        const item: SessionSnapshot = {
            profile_result: this.profileResult,
            scan_metadata: {
                scan_id: this.selectedScan.scan_id,
                date: this.selectedScan.date,
                request: {
                    live: false,
                    scan_time: request.scan_time,
                    band: request.band
                }
            }
        };
        this.sessionHistory = this.sessionHistory.filter(
            (value) => value.scan_metadata.scan_id !== item.scan_metadata.scan_id
        );
        this.sessionHistory.push(item);
        this.sessionHistory = this.sessionHistory.slice(-5);
    }

    async startManualRecon(band: string, scanTime: number): Promise<any> {
        const allowed = this.settings && this.settings.supported_bands.some(
            (value) => value.value === band
        );
        if (!allowed) {
            throw {code: 'band_not_supported', message: 'Select a configured band.'};
        }
        await this.refreshReconStatus();
        if (this.reconStatus.scanRunning || this.reconStatus.captureRunning) {
            throw {code: 'recon_busy', message: 'Recon or capture is already running.'};
        }
        const response = await this.api.nativePost<any>('/api/recon/start', {
            live: false,
            scan_time: scanTime,
            band
        });
        this.log('success', 'Recon started', `${scanTime} seconds.`);
        return response;
    }

    async stopRecon(): Promise<any> {
        const result = await this.api.nativePost<any>('/api/recon/stop', {});
        this.log('warning', 'Recon stop requested');
        return result;
    }
}
