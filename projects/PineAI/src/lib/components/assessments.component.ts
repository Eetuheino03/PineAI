import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-assessments',
    templateUrl: './assessments.component.html',
    styleUrls: ['./shared.css']
})
export class AssessmentsComponent {
    form: FormGroup;
    busy = false;
    editMode = false;
    showArchived = false;
    errorMessage = '';
    successMessage = '';

    constructor(public pineai: PineAIService, formBuilder: FormBuilder) {
        this.form = formBuilder.group({
            name: ['', [Validators.required, Validators.maxLength(100)]],
            location: ['', Validators.maxLength(200)],
            notes: ['', Validators.maxLength(2000)]
        });
    }

    newAssessment(): void {
        this.editMode = false;
        this.errorMessage = '';
        this.successMessage = '';
        this.form.reset({name: '', location: '', notes: ''});
    }

    async refresh(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        try {
            await this.pineai.refreshAssessments(this.showArchived);
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }

    async select(assessmentId: string): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            const assessment = await this.pineai.selectAssessment(assessmentId);
            this.editMode = true;
            this.form.setValue({
                name: assessment.name || '',
                location: assessment.location || '',
                notes: assessment.notes || ''
            });
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }

    async save(): Promise<void> {
        if (this.form.invalid) {
            this.form.markAllAsTouched();
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            if (this.editMode && this.pineai.activeAssessment) {
                await this.pineai.updateAssessment(this.form.value);
                this.successMessage = 'Assessment updated.';
            } else {
                await this.pineai.createAssessment(this.form.value);
                this.editMode = true;
                this.successMessage = 'Assessment created.';
            }
        } catch (error) {
            const failure = this.pineai.error(error);
            if (failure.code === 'revision_conflict') {
                this.errorMessage =
                    'revision_conflict: The assessment changed. Latest data was loaded; review it before retrying.';
                this.loadActiveForm();
            } else {
                this.errorMessage = `${failure.code}: ${failure.message}`;
            }
        } finally {
            this.busy = false;
        }
    }

    async archive(): Promise<void> {
        if (!this.pineai.activeAssessment ||
            !window.confirm(`Archive "${this.pineai.activeAssessment.name}"?`)) {
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        try {
            await this.pineai.archiveAssessment();
            this.newAssessment();
            this.successMessage = 'Assessment archived.';
        } catch (error) {
            const failure = this.pineai.error(error);
            this.errorMessage = failure.code === 'revision_conflict'
                ? 'revision_conflict: Latest assessment state was loaded. Review it before retrying.'
                : `${failure.code}: ${failure.message}`;
            this.loadActiveForm();
        } finally {
            this.busy = false;
        }
    }

    private loadActiveForm(): void {
        const value = this.pineai.activeAssessment;
        if (!value) {
            return;
        }
        this.editMode = true;
        this.form.setValue({
            name: value.name || '',
            location: value.location || '',
            notes: value.notes || ''
        });
    }
}
