import { Component, OnInit } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-PineAI',
    templateUrl: './PineAI.component.html',
    styleUrls: ['./PineAI.component.css']
})
export class PineAIComponent implements OnInit {
    startupError = '';

    constructor(public pineai: PineAIService) {}

    async ngOnInit(): Promise<void> {
        try {
            await this.pineai.initialize();
        } catch (error) {
            const failure = this.pineai.error(error);
            this.startupError = `${failure.code}: ${failure.message}`;
        }
    }

    async retry(): Promise<void> {
        this.startupError = '';
        try {
            await this.pineai.initialize();
        } catch (error) {
            const failure = this.pineai.error(error);
            this.startupError = `${failure.code}: ${failure.message}`;
        }
    }
}
