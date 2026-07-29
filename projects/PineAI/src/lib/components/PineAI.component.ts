import { Component, OnInit } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pine-ai',
    templateUrl: './PineAI.component.html',
    styleUrls: ['./PineAI.component.css']
})
export class PineAIComponent implements OnInit {
    startupError = '';
    mode: 'guided' | 'expert' = 'guided';

    async ngOnInit(): Promise<void> {
        await this.initialize();
    }

    async retry(): Promise<void> {
        await this.initialize();
    }

    private async initialize(): Promise<void> {
        this.startupError = '';
        try {
            await this.pineai.initialize();
        } catch (error) {
            this.startupError = this.pineai.errorText(error);
        }
    }
}
