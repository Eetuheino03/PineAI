import { Component } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-targets',
    templateUrl: './targets.component.html',
    styleUrls: ['./shared.css']
})
export class TargetsComponent {
    aiEnabled = true;
    busy = false;
    errorMessage = '';
    preview: any = null;

    constructor(public pineai: PineAIService) {}

    async profile(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        this.preview = null;
        try {
            await this.pineai.profileSelectedScan(this.aiEnabled);
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
            this.preview = await this.pineai.prepareProfile();
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    selected(targetId: string): boolean {
        return this.pineai.selectedTargetIds.indexOf(targetId) !== -1;
    }

    toggle(targetId: string, checked: boolean): void {
        this.pineai.toggleTarget(targetId, checked);
    }

    targetName(target: any): string {
        return target.hidden ? `Hidden target ${target.target_id}` :
            (target.ssid || target.target_id);
    }

    private showError(error: any): void {
        const failure = this.pineai.error(error);
        this.errorMessage = `${failure.code}: ${failure.message}`;
    }
}
