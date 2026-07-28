import { Component } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-activity',
    templateUrl: './activity.component.html',
    styleUrls: ['./shared.css']
})
export class ActivityComponent {
    constructor(public pineai: PineAIService) {}

    get auditEvents(): any[] {
        return this.pineai.activeAssessment &&
            Array.isArray(this.pineai.activeAssessment.events)
            ? this.pineai.activeAssessment.events.slice().reverse()
            : [];
    }

    eventTitle(event: any): string {
        return event.event_type || event.type || event.action || 'assessment_event';
    }

    eventTime(event: any): string {
        return event.recorded_at || event.timestamp || event.time ||
            event.created_at || '—';
    }
}
