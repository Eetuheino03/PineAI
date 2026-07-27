export interface SupportedBand {
    value: string;
    covers: Array<'2.4' | '5'>;
    is_default: boolean;
}

export interface PineAISettings {
    schema_version: string;
    model: string;
    language: 'en' | 'fi';
    share_ssids: boolean;
    max_ai_targets: number;
    supported_bands: SupportedBand[];
    api_key_configured: boolean;
    api_key_source: 'none' | 'file' | 'environment';
}

export interface ReconStatus {
    captureRunning: boolean;
    scanRunning: boolean;
    continuous: boolean;
    scanPercent: number;
    scanID: number;
}

export interface ReconScan {
    scan_id: number;
    date: string;
}

export interface ActivityEntry {
    time: string;
    level: 'info' | 'success' | 'warning' | 'error';
    title: string;
    detail: string;
}

export interface SessionSnapshot {
    profile_result: any;
    scan_metadata: {
        scan_id: number;
        date: string;
        request: {
            live: false;
            scan_time: number;
            band: string;
        };
    };
}

export interface FrontendError {
    code: string;
    message: string;
}
