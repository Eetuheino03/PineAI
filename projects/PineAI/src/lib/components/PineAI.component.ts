import { Component, OnInit } from '@angular/core';
import { ApiService } from '../services/api.service';

@Component({
    selector: 'lib-PineAI',
    templateUrl: './PineAI.component.html',
    styleUrls: ['./PineAI.component.css']
})
export class PineAIComponent implements OnInit {
    constructor(private API: ApiService) { }

    backendStatus = 'Not checked';

    checkBackend(): void {
        this.API.request({
            module: 'PineAI',
            action: 'health'
        }, (response) => {
            this.backendStatus = response && response.status
                ? response.status
                : 'Unexpected response';
        });
    }

    ngOnInit() {
    }
}
