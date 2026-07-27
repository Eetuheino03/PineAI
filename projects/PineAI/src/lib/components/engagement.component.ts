import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-engagement',
    templateUrl: './engagement.component.html',
    styleUrls: ['./shared.css']
})
export class EngagementComponent {
    form: FormGroup;
    busy = false;
    errorMessage = '';
    editMode = false;

    constructor(public pineai: PineAIService, formBuilder: FormBuilder) {
        const start = new Date();
        const end = new Date(start.getTime() + 4 * 60 * 60 * 1000);
        this.form = formBuilder.group({
            name: ['', [Validators.required, Validators.maxLength(100)]],
            objectives: [[], Validators.required],
            objective_notes: ['', Validators.maxLength(1000)],
            authorized_target_ids: [[], Validators.required],
            allowed_actions: [['collect_additional_recon'], Validators.required],
            disruption_allowed: [false],
            authorization_reference: ['', [Validators.required, Validators.maxLength(200)]],
            valid_from: [this.toLocalInput(start.toISOString()), Validators.required],
            valid_until: [this.toLocalInput(end.toISOString()), Validators.required]
        });
    }

    label(value: string): string {
        return value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
    }

    availableTargets(): any[] {
        return this.pineai.profileResult && Array.isArray(this.pineai.profileResult.targets)
            ? this.pineai.profileResult.targets : [];
    }

    newEngagement(): void {
        this.editMode = false;
        this.errorMessage = '';
        this.form.patchValue({
            name: '',
            objectives: [],
            objective_notes: '',
            authorized_target_ids: this.pineai.selectedTargetIds.slice(),
            allowed_actions: ['collect_additional_recon'],
            disruption_allowed: false,
            authorization_reference: ''
        });
    }

    async select(engagementId: string): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        try {
            const engagement = await this.pineai.selectEngagement(engagementId);
            this.editMode = true;
            this.form.setValue({
                name: engagement.name,
                objectives: engagement.objectives,
                objective_notes: engagement.objective_notes,
                authorized_target_ids: engagement.authorized_target_ids,
                allowed_actions: engagement.allowed_actions,
                disruption_allowed: engagement.disruption_allowed,
                authorization_reference: engagement.authorization_reference,
                valid_from: this.toLocalInput(engagement.valid_from),
                valid_until: this.toLocalInput(engagement.valid_until)
            });
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    async save(): Promise<void> {
        if (this.form.invalid) {
            this.form.markAllAsTouched();
            return;
        }
        const value = Object.assign({}, this.form.value, {
            valid_from: new Date(this.form.value.valid_from).toISOString(),
            valid_until: new Date(this.form.value.valid_until).toISOString()
        });
        this.busy = true;
        this.errorMessage = '';
        try {
            if (this.editMode && this.pineai.activeEngagement) {
                await this.pineai.updateEngagement(value);
            } else {
                await this.pineai.createEngagement(value);
                this.editMode = true;
            }
        } catch (error) {
            const failure = this.pineai.error(error);
            if (failure.code === 'revision_conflict') {
                this.errorMessage =
                    'revision_conflict: The engagement changed. Latest data was loaded; review and retry.';
                if (this.pineai.activeEngagement) {
                    await this.select(this.pineai.activeEngagement.engagement_id);
                }
            } else {
                this.errorMessage = `${failure.code}: ${failure.message}`;
            }
        } finally {
            this.busy = false;
        }
    }

    async archive(): Promise<void> {
        if (!this.pineai.activeEngagement) {
            return;
        }
        if (!window.confirm(
            `Archive "${this.pineai.activeEngagement.name}"? This cannot be undone through PineAI.`
        )) {
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        try {
            await this.pineai.archiveEngagement();
            this.newEngagement();
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    private toLocalInput(value: string): string {
        const date = new Date(value);
        const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
        return local.toISOString().slice(0, 16);
    }

    private showError(error: any): void {
        const failure = this.pineai.error(error);
        this.errorMessage = `${failure.code}: ${failure.message}`;
    }
}
