import { Component } from '@angular/core';
import { FormControl, Validators } from '@angular/forms';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-baselines',
    templateUrl: './baselines.component.html',
    styleUrls: ['./shared.css']
})
export class BaselinesComponent {
    label = new FormControl('', Validators.maxLength(128));
    busy = false;
    errorMessage = '';
    successMessage = '';

    constructor(public pineai: PineAIService) {}

    async refresh(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        try {
            await this.pineai.refreshBaselines();
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }

    async create(): Promise<void> {
        if (this.label.invalid) {
            this.label.markAsTouched();
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await this.pineai.createBaselineVersion(this.label.value || '');
            this.label.reset('');
            this.successMessage =
                'Immutable baseline version created. Activate it explicitly before comparison.';
        } catch (error) {
            this.handleError(error);
        } finally {
            this.busy = false;
        }
    }

    async activate(value: any): Promise<void> {
        const id = this.pineai.baselineId(value);
        if (!id || !window.confirm(
            `Activate baseline "${id}"? Future comparisons will use this version.`
        )) {
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await this.pineai.activateBaselineVersion(id);
            this.successMessage = `Baseline ${id} is active.`;
        } catch (error) {
            this.handleError(error);
        } finally {
            this.busy = false;
        }
    }

    private handleError(error: any): void {
        const failure = this.pineai.error(error);
        this.errorMessage = failure.code === 'revision_conflict'
            ? 'revision_conflict: Assessment state changed and was refreshed. Review before retrying.'
            : `${failure.code}: ${failure.message}`;
    }
}
