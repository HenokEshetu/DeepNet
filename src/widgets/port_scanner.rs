use eframe::egui;
use crate::scanner::{PortScanner as NativeScanner, ScanType};
use std::sync::{Arc, Mutex};
use std::thread;
use crossbeam_channel::{bounded, Receiver};

pub struct PortScanner {
    target: String,
    port_range: (u16, u16),
    scan_type: ScanType,
    threads: usize,
    results: Arc<Mutex<Vec<(u16, String)>>>,
    progress: f32,
    status: String,
    receiver: Option<Receiver<(u16, String)>>,
    scanning: bool,
}

impl Default for PortScanner {
    fn default() -> Self {
        Self {
            target: "127.0.0.1".to_string(),
            port_range: (1, 1024),
            scan_type: ScanType::TcpSyn,
            threads: 100,
            results: Arc::new(Mutex::new(Vec::new())),
            progress: 0.0,
            status: "Ready".to_string(),
            receiver: None,
            scanning: false,
        }
    }
}

impl PortScanner {
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Port Scanner");
        
        egui::Grid::new("scanner_grid")
            .num_columns(2)
            .spacing([20.0, 10.0])
            .show(ui, |ui| {
                ui.label("Target:");
                ui.text_edit_singleline(&mut self.target);
                ui.end_row();
                
                ui.label("Port Range:");
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut self.port_range.0).clamp_range(1..=65535));
                    ui.label("to");
                    ui.add(egui::DragValue::new(&mut self.port_range.1).clamp_range(1..=65535));
                });
                ui.end_row();
                
                ui.label("Scan Type:");
                egui::ComboBox::from_id_source("scan_type")
                    .selected_text(format!("{:?}", self.scan_type))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.scan_type, ScanType::TcpSyn, "TCP SYN");
                        ui.selectable_value(&mut self.scan_type, ScanType::TcpConnect, "TCP Connect");
                        ui.selectable_value(&mut self.scan_type, ScanType::Udp, "UDP");
                    });
                ui.end_row();
                
                ui.label("Threads:");
                ui.add(egui::DragValue::new(&mut self.threads).clamp_range(1..=1000));
                ui.end_row();
            });
        
        ui.separator();
        
        if ui.button("Start Scan").clicked() && !self.scanning {
            self.start_scan();
        }
        
        ui.add_enabled_ui(self.scanning, |ui| {
            if ui.button("Stop Scan").clicked() {
                self.stop_scan();
            }
        });
        
        ui.label(&self.status);
        ui.add(egui::ProgressBar::new(self.progress).show_percentage());
        
        ui.separator();
        
        egui::ScrollArea::vertical().show(ui, |ui| {
            let results = self.results.lock().unwrap();
            egui::Grid::new("results_grid")
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Port");
                    ui.strong("Protocol");
                    ui.strong("Status");
                    ui.end_row();
                    
                    for (port, status) in results.iter() {
                        ui.label(port.to_string());
                        ui.label(if *port < 1024 { "Well-known" } else { "Registered" });
                        ui.label(status);
                        ui.end_row();
                    }
                });
        });
    }
    
    fn start_scan(&mut self) {
        self.scanning = true;
        self.status = "Scanning...".to_string();
        self.progress = 0.0;
        self.results.lock().unwrap().clear();
        
        let (tx, rx) = bounded(100);
        self.receiver = Some(rx);
        
        let target = self.target.clone();
        let port_range = self.port_range;
        let scan_type = self.scan_type;
        let threads = self.threads;
        let results = self.results.clone();
        let status = self.status.clone();
        
        thread::spawn(move || {
            let mut scanner = NativeScanner::new(&target, port_range, scan_type, threads);
            scanner.scan(tx);
            
            let mut results = results.lock().unwrap();
            *results = scanner.get_results();
        });
    }
    
    fn stop_scan(&mut self) {
        self.scanning = false;
        self.status = "Scan stopped".to_string();
    }
}
