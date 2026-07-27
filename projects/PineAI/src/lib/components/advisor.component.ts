import { Component } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-advisor',
    templateUrl: './advisor.component.html',
    styleUrls: ['./shared.css']
})
export class AdvisorComponent {
    aiEnabled = true;
    busy = false;
    errorMessage = '';
    preview: any = null;

    constructor(public pineai: PineAIService) {}

    async generate(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        this.preview = null;
        try {
            await this.pineai.advise(this.aiEnabled);
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    async showPreview(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        try {
            this.preview = await this.pineai.prepareAdvice();
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    isSelected(pathId: string): boolean {
        return this.pineai.selectedPathIds.indexOf(pathId) !== -1;
    }

    selectAdaptive(path: any, targetId: string, checked: boolean): void {
        if (checked) {
            const sameTargetIds = [];
            for (const targetResult of this.pineai.advisorResult.target_results || []) {
                if (targetResult.target_id === targetId) {
                    for (const candidate of targetResult.paths || []) {
                        sameTargetIds.push(candidate.path_id);
                    }
                }
            }
            this.pineai.selectedPathIds = this.pineai.selectedPathIds.filter(
                (value) => sameTargetIds.indexOf(value) === -1
            );
        }
        this.pineai.togglePath(path.path_id, checked);
    }

    async record(
        eventType: 'action_started' | 'action_completed' | 'action_failed' | 'action_aborted',
        targetId: string,
        step: any,
        path: any
    ): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        try {
            await this.pineai.appendEvent({
                event_type: eventType,
                summary: `Operator recorded ${eventType.replace('action_', '')} for ${step.action_id}.`,
                target_id: targetId,
                action_id: step.action_id,
                evidence_ids: path.evidence_ids || []
            });
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    private showError(error: any): void {
        const failure = this.pineai.error(error);
        this.errorMessage = `${failure.code}: ${failure.message}`;
    }
}
