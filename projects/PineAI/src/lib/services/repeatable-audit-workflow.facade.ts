import {Injectable} from '@angular/core';
import {ReconScan} from '../models';
import {
    AuditRunAssignmentRequest,
    SessionReconSelection
} from '../repeatable-audit.models';

@Injectable({providedIn: 'root'})
export class RepeatableAuditWorkflowFacade {
    readonly maxRawScans = 5;
    assessmentId = '';
    selectedStep = 0;
    selectedPointIds: string[] = [];
    assignments: {[pointId: string]: AuditRunAssignmentRequest} = {};
    selectedScanByMeasurement: {[measurementId: string]: string} = {};
    messages: {[key: string]: string} = {};
    errors: {[key: string]: string} = {};
    private rawScans: {[scanId: string]: SessionReconSelection} = {};
    private rawScanOrder: string[] = [];

    resetForAssessment(assessmentId: string): void {
        if (assessmentId === this.assessmentId) {
            return;
        }
        this.assessmentId = assessmentId;
        this.selectedStep = 0;
        this.selectedPointIds = [];
        this.assignments = {};
        this.selectedScanByMeasurement = {};
        this.messages = {};
        this.errors = {};
        this.clearRawScans();
    }

    selectPoint(pointId: string, selected: boolean): void {
        const next = this.selectedPointIds.filter((value) => value !== pointId);
        if (selected) {
            next.push(pointId);
        } else {
            delete this.assignments[pointId];
        }
        this.selectedPointIds = next.slice(0, 16);
    }

    pointSelected(pointId: string): boolean {
        return this.selectedPointIds.indexOf(pointId) >= 0;
    }

    setAssignment(value: AuditRunAssignmentRequest): void {
        if (!this.pointSelected(value.measurement_point_id)) {
            this.selectPoint(value.measurement_point_id, true);
        }
        this.assignments[value.measurement_point_id] = Object.assign({}, value);
        this.assignments = Object.assign({}, this.assignments);
    }

    assignment(pointId: string): AuditRunAssignmentRequest | null {
        return this.assignments[pointId] || null;
    }

    validAssignments(): AuditRunAssignmentRequest[] {
        return this.selectedPointIds.map((pointId) => this.assignments[pointId])
            .filter((value) => !!value &&
                !!value.measurement_profile_id &&
                !!value.measurement_profile_version_id &&
                !!value.baseline_version_id);
    }

    rememberRawScan(scan: ReconScan, data: any): void {
        const id = String(scan.scan_id);
        this.rawScans[id] = {scan, data};
        this.rawScanOrder = this.rawScanOrder.filter((value) => value !== id);
        this.rawScanOrder.push(id);
        while (this.rawScanOrder.length > this.maxRawScans) {
            const removed = this.rawScanOrder.shift();
            delete this.rawScans[removed];
            Object.keys(this.selectedScanByMeasurement).forEach((measurementId) => {
                if (this.selectedScanByMeasurement[measurementId] === removed) {
                    delete this.selectedScanByMeasurement[measurementId];
                }
            });
        }
    }

    selectScan(measurementId: string, scanId: string): void {
        this.selectedScanByMeasurement[measurementId] = scanId;
        this.selectedScanByMeasurement = Object.assign(
            {}, this.selectedScanByMeasurement
        );
    }

    selectedScan(measurementId: string): SessionReconSelection | null {
        const scanId = this.selectedScanByMeasurement[measurementId];
        return scanId && this.rawScans[scanId]
            ? this.rawScans[scanId] : null;
    }

    rawScanCount(): number {
        return this.rawScanOrder.length;
    }

    clearRawScans(): void {
        this.rawScans = {};
        this.rawScanOrder = [];
        this.selectedScanByMeasurement = {};
    }

    setMessage(area: string, message: string): void {
        this.messages[area] = message;
        delete this.errors[area];
        this.messages = Object.assign({}, this.messages);
        this.errors = Object.assign({}, this.errors);
    }

    setError(area: string, error: {code: string; message: string}): void {
        this.errors[area] = `${error.code}: ${error.message}`;
        delete this.messages[area];
        this.errors = Object.assign({}, this.errors);
        this.messages = Object.assign({}, this.messages);
    }

    clearFeedback(area: string): void {
        delete this.errors[area];
        delete this.messages[area];
        this.errors = Object.assign({}, this.errors);
        this.messages = Object.assign({}, this.messages);
    }
}
