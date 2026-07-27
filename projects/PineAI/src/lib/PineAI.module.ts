import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { PineAIComponent } from './components/PineAI.component';
import { RouterModule, Routes } from '@angular/router';

import {MaterialModule} from './modules/material/material.module';
import {FlexLayoutModule} from '@angular/flex-layout';

import {FormsModule} from '@angular/forms';

const routes: Routes = [
    { path: '', component: PineAIComponent }
];

@NgModule({
    declarations: [PineAIComponent],
    imports: [
        CommonModule,
        RouterModule.forChild(routes),
        MaterialModule,
        FlexLayoutModule,
        FormsModule,
    ],
    exports: [PineAIComponent]
})
export class PineAIModule { }
