import { Component } from '@angular/core';
import { FormControl, Validators } from '@angular/forms';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-activity',
    templateUrl: './activity.component.html',
    styleUrls: ['./shared.css']
})
export class ActivityComponent {
    note = new FormControl('', [Validators.required, Validators.maxLength(1000)]);
    busy = false;
    errorMessage = '';

    constructor(public pineai: PineAIService) {}

    async addNote(): Promise<void> {
        if (this.note.invalid || !this.pineai.activeEngagement) {
            this.note.markAsTouched();
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        try {
            await this.pineai.appendEvent({
                event_type: 'operator_note',
                summary: this.note.value,
                target_id: null,
                action_id: null,
                evidence_ids: []
            });
            this.note.reset('');
        } catch (error) {
            const failure = this.pineai.error(error);
            this.errorMessage = `${failure.code}: ${failure.message}`;
        } finally {
            this.busy = false;
        }
    }
}
