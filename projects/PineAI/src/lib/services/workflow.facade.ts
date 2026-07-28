import {Injectable} from '@angular/core';
import {BehaviorSubject, Observable} from 'rxjs';
import {
    Assessment,
    MeasurementProfile,
    ReconScan,
    WorkflowScanSelection,
    WorkflowState,
    WorkflowStepKey,
    WorkflowStepState
} from '../models';

const STEP_ORDER: WorkflowStepKey[] = [
    'assessment',
    'measurement_profile',
    'recon_scans',
    'baseline_comparison',
    'inventory_policy',
    'analysis_evidence',
    'report'
];

function initialState(): WorkflowState {
    return {
        mode: 'baseline',
        current_step: 'assessment',
        assessment_id: '',
        assessment_revision: null,
        measurement_profile_id: '',
        measurement_profile_revision: null,
        selected_scans: [],
        consensus_preview_digest: '',
        baseline_version_id: '',
        assurance_profile_revision: null,
        assurance_profile_confirmed: false,
        comparison_preview_ready: false,
        comparison_id: '',
        analysis_saved: false,
        report_scope_digest: '',
        busy_action: '',
        step_states: {
            assessment: 'active',
            measurement_profile: 'blocked',
            recon_scans: 'blocked',
            baseline_comparison: 'blocked',
            inventory_policy: 'blocked',
            analysis_evidence: 'blocked',
            report: 'blocked'
        }
    };
}

@Injectable({providedIn: 'root'})
export class WorkflowFacade {
    private stateSubject = new BehaviorSubject<WorkflowState>(initialState());
    private rawScans: {[scanId: string]: any} = {};
    private rawScanOrder: string[] = [];

    readonly state$: Observable<WorkflowState> = this.stateSubject.asObservable();

    get snapshot(): WorkflowState {
        return this.stateSubject.value;
    }

    setAssessment(assessment: Assessment | null, activeBaselineId: string = ''): void {
        const nextId = assessment ? assessment.assessment_id : '';
        const changed = nextId !== this.snapshot.assessment_id;
        if (!changed && assessment) {
            this.patch({
                assessment_revision: assessment.revision,
                baseline_version_id: activeBaselineId || '',
                mode: activeBaselineId ? 'comparison' : 'baseline'
            });
            this.recalculate();
            return;
        }
        this.clearRawScans();
        const next = initialState();
        next.assessment_id = nextId;
        next.assessment_revision = assessment ? assessment.revision : null;
        next.baseline_version_id = activeBaselineId || '';
        next.mode = activeBaselineId ? 'comparison' : 'baseline';
        next.current_step = assessment ? 'measurement_profile' : 'assessment';
        next.step_states.assessment = assessment ? 'complete' : 'active';
        next.step_states.measurement_profile = assessment ? 'active' : 'blocked';
        this.emit(next);
    }

    selectMeasurementProfile(profile: MeasurementProfile | null): void {
        const patch: Partial<WorkflowState> = {
            measurement_profile_id: profile
                ? profile.measurement_profile_id || profile.profile_id || '' : '',
            measurement_profile_revision: profile ? profile.revision : null
        };
        this.patch(patch);
        this.recalculate();
    }

    setCurrentStep(step: WorkflowStepKey): void {
        if (STEP_ORDER.indexOf(step) === -1) {
            return;
        }
        this.patch({current_step: step});
        this.recalculate();
    }

    next(): void {
        const index = STEP_ORDER.indexOf(this.snapshot.current_step);
        if (index >= 0 && index < STEP_ORDER.length - 1) {
            this.setCurrentStep(STEP_ORDER[index + 1]);
        }
    }

    previous(): void {
        const index = STEP_ORDER.indexOf(this.snapshot.current_step);
        if (index > 0) {
            this.setCurrentStep(STEP_ORDER[index - 1]);
        }
    }

    setBusy(action: string): void {
        this.patch({busy_action: action || ''});
    }

    rememberRawScan(scan: ReconScan, data: any): void {
        const id = String(scan.scan_id);
        if (!this.rawScans[id] && this.rawScanOrder.length >= 5) {
            const oldest = this.rawScanOrder.shift();
            if (oldest) {
                delete this.rawScans[oldest];
                const selections = this.snapshot.selected_scans.filter(
                    (value) => value.scan_id !== oldest
                );
                this.patch({selected_scans: selections});
            }
        }
        this.rawScans[id] = data;
        this.rawScanOrder = this.rawScanOrder.filter((value) => value !== id);
        this.rawScanOrder.push(id);
        const current = this.snapshot.selected_scans.filter(
            (value) => value.scan_id !== id
        );
        current.push({scan_id: id, scan, loaded: true});
        this.patch({selected_scans: current});
        this.recalculate();
    }

    markScanError(scan: ReconScan, error: any): void {
        const id = String(scan.scan_id);
        const current = this.snapshot.selected_scans.filter(
            (value) => value.scan_id !== id
        );
        const selection: WorkflowScanSelection = {
            scan_id: id,
            scan,
            loaded: false,
            error: {
                code: error && error.code ? error.code : 'request_failed',
                message: error && error.message ? error.message : 'The scan could not be loaded.'
            }
        };
        current.push(selection);
        this.patch({selected_scans: current});
        this.recalculate();
    }

    removeScan(scanId: string): void {
        delete this.rawScans[scanId];
        this.rawScanOrder = this.rawScanOrder.filter((value) => value !== scanId);
        this.patch({
            selected_scans: this.snapshot.selected_scans.filter(
                (value) => value.scan_id !== scanId
            ),
            consensus_preview_digest: '',
            comparison_id: '',
            report_scope_digest: ''
        });
        this.recalculate();
    }

    rawScan(scanId: string): any {
        return this.rawScans[scanId];
    }

    selectedRawScans(): Array<{scan: ReconScan, data: any}> {
        return this.snapshot.selected_scans
            .filter((value) => value.loaded && this.rawScans[value.scan_id])
            .map((value) => ({
                scan: value.scan,
                data: this.rawScans[value.scan_id]
            }));
    }

    clearRawScans(): void {
        this.rawScans = {};
        this.rawScanOrder = [];
    }

    clearSelectedScans(): void {
        this.clearRawScans();
        this.patch({
            selected_scans: [],
            consensus_preview_digest: '',
            comparison_preview_ready: false,
            comparison_id: '',
            analysis_saved: false,
            report_scope_digest: ''
        });
        this.recalculate();
    }

    setConsensusPreview(digest: string): void {
        this.patch({consensus_preview_digest: digest || ''});
        this.recalculate();
    }

    setBaselineVersion(id: string): void {
        this.patch({
            baseline_version_id: id || '',
            mode: id ? 'comparison' : 'baseline'
        });
        this.recalculate();
    }

    setAssuranceProfileRevision(revision: number | null): void {
        const unchanged = this.snapshot.assurance_profile_revision === revision;
        this.patch({
            assurance_profile_revision: revision,
            assurance_profile_confirmed:
                unchanged && this.snapshot.assurance_profile_confirmed
        });
        this.recalculate();
    }

    confirmAssuranceProfile(): void {
        this.patch({assurance_profile_confirmed: true});
        this.recalculate();
    }

    setComparison(
        id: string,
        previewReady: boolean = true,
        analysisSaved: boolean = false
    ): void {
        this.patch({
            comparison_id: id || '',
            comparison_preview_ready: previewReady,
            analysis_saved: analysisSaved,
            report_scope_digest: ''
        });
        this.recalculate();
    }

    setReportScopeDigest(digest: string): void {
        this.patch({report_scope_digest: digest || ''});
        this.recalculate();
    }

    canProceed(step: WorkflowStepKey): boolean {
        const value = this.snapshot;
        if (step === 'assessment') {
            return !!value.assessment_id;
        }
        if (step === 'measurement_profile') {
            return !!value.assessment_id && !!value.measurement_profile_id;
        }
        if (step === 'recon_scans') {
            const loaded = value.selected_scans.filter((scan) => scan.loaded).length;
            return value.mode === 'baseline'
                ? loaded >= 2 && loaded <= 5
                : loaded === 1;
        }
        if (step === 'baseline_comparison') {
            return value.mode === 'baseline'
                ? !!value.consensus_preview_digest || !!value.baseline_version_id
                : value.comparison_preview_ready;
        }
        if (step === 'inventory_policy') {
            return value.assurance_profile_confirmed;
        }
        if (step === 'analysis_evidence') {
            return value.analysis_saved && !!value.comparison_id;
        }
        if (step === 'report') {
            return !!value.report_scope_digest;
        }
        return false;
    }

    private recalculate(): void {
        const value = this.snapshot;
        const states: {[key: string]: WorkflowStepState} = {};
        let priorComplete = true;
        for (const step of STEP_ORDER) {
            const complete = this.canProceed(step);
            if (step === value.current_step) {
                states[step] = 'active';
            } else if (complete) {
                states[step] = 'complete';
            } else if (priorComplete) {
                states[step] = 'ready';
            } else {
                states[step] = 'blocked';
            }
            priorComplete = priorComplete && complete;
        }
        this.patch({step_states: states}, false);
    }

    private patch(patch: Partial<WorkflowState>, emit: boolean = true): void {
        const next = Object.assign({}, this.snapshot, patch);
        if (emit) {
            this.emit(next);
        } else {
            this.stateSubject.next(next);
        }
    }

    private emit(next: WorkflowState): void {
        this.stateSubject.next(next);
    }
}
