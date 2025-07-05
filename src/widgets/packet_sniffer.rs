use eframe::egui;
use crate::sniffer::{PacketSniffer as NativeSniffer, PacketInfo};
use std::sync::{Arc, Mutex};
use std::thread;
use crossbeam_channel::{bounded, Receiver};

pub struct PacketSniffer {
    interface: String,
    interfaces: Vec<String>,
    filter: String,
    results: Arc<Mutex<Vec<PacketInfo>>>,
    receiver: Option<Receiver<PacketInfo>>,
    sniffing: bool,
    packet_count: usize,
}

impl Default for PacketSniffer {
    fn default() -> Self {
        let interfaces = pnet_datalink::interfaces()
            .iter()
            .filter(|iface| iface.is_up() && !iface.is_loopback())
            .map(|iface| iface.name.clone())
            .collect::<Vec<_>>();
        
        let interface = interfaces.first().cloned().unwrap_or_default();
        
        Self {
            interface,
            interfaces,
            filter: "".to_string(),
            results: Arc::new(Mutex::new(Vec::new())),
            receiver: None,
            sniffing: false,
            packet_count: 0,
        }
    }
}

impl PacketSniffer {
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Packet Sniffer");
        
        egui::Grid::new("sniffer_grid")
            .num_columns(2)
            .spacing([20.0, 10.0])
            .show(ui, |ui| {
                ui.label("Interface:");
                egui::ComboBox::from_id_source("interface")
                    .selected_text(&self.interface)
                    .show_ui(ui, |ui| {
                        for iface in &self.interfaces {
                            ui.selectable_value(&mut self.interface, iface.clone(), iface);
                        }
                    });
                ui.end_row();
                
                ui.label("Filter (BPF):");
                ui.text_edit_singleline(&mut self.filter);
                ui.end_row();
            });
        
        ui.separator();
        
        if ui.button("Start Sniffing").clicked() && !self.sniffing {
            self.start_sniffing();
        }
        
        ui.add_enabled_ui(self.sniffing, |ui| {
            if ui.button("Stop Sniffing").clicked() {
                self.stop_sniffing();
            }
        });
        
        ui.label(format!("Packets captured: {}", self.packet_count));
        
        ui.separator();
        
        egui::ScrollArea::both().show(ui, |ui| {
            let results = self.results.lock().unwrap();
            
            egui::Grid::new("packet_grid")
                .num_columns(6)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Time");
                    ui.strong("Source");
                    ui.strong("Destination");
                    ui.strong("Protocol");
                    ui.strong("Length");
                    ui.strong("Info");
                    ui.end_row();
                    
                    for packet in results.iter() {
                        ui.label(&packet.timestamp);
                        ui.label(&packet.source);
                        ui.label(&packet.destination);
                        ui.label(&packet.protocol);
                        ui.label(packet.length.to_string());
                        ui.label(&packet.info);
                        ui.end_row();
                    }
                });
        });
    }
    
    fn start_sniffing(&mut self) {
        self.sniffing = true;
        self.packet_count = 0;
        self.results.lock().unwrap().clear();
        
        let (tx, rx) = bounded(100);
        self.receiver = Some(rx);
        
        let interface = self.interface.clone();
        let filter = self.filter.clone();
        let results = self.results.clone();
        
        thread::spawn(move || {
            let mut sniffer = NativeSniffer::new(&interface, &filter);
            sniffer.start(tx);
        });
    }
    
    fn stop_sniffing(&mut self) {
        self.sniffing = false;
    }
}
