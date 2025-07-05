use eframe::egui;
use crate::crafter::PacketCrafter as NativeCrafter;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Raw,
}

pub struct PacketCrafter {
    source_ip: String,
    dest_ip: String,
    source_port: u16,
    dest_port: u16,
    protocol: Protocol,
    payload: String,
    count: u32,
    delay: u32,
    results: Vec<String>,
    crafting: bool,
}

impl Default for PacketCrafter {
    fn default() -> Self {
        Self {
            source_ip: "192.168.1.100".to_string(),
            dest_ip: "192.168.1.1".to_string(),
            source_port: 54321,
            dest_port: 80,
            protocol: Protocol::Tcp,
            payload: "DeepNet Packet".to_string(),
            count: 5,
            delay: 100,
            results: Vec::new(),
            crafting: false,
        }
    }
}

impl PacketCrafter {
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Packet Crafter");
        
        egui::Grid::new("crafter_grid")
            .num_columns(2)
            .spacing([20.0, 10.0])
            .show(ui, |ui| {
                ui.label("Source IP:");
                ui.text_edit_singleline(&mut self.source_ip);
                ui.end_row();
                
                ui.label("Destination IP:");
                ui.text_edit_singleline(&mut self.dest_ip);
                ui.end_row();
                
                ui.label("Source Port:");
                ui.add(egui::DragValue::new(&mut self.source_port).clamp_range(1..=65535));
                ui.end_row();
                
                ui.label("Destination Port:");
                ui.add(egui::DragValue::new(&mut self.dest_port).clamp_range(1..=65535));
                ui.end_row();
                
                ui.label("Protocol:");
                egui::ComboBox::from_id_source("protocol")
                    .selected_text(format!("{:?}", self.protocol))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.protocol, Protocol::Tcp, "TCP");
                        ui.selectable_value(&mut self.protocol, Protocol::Udp, "UDP");
                        ui.selectable_value(&mut self.protocol, Protocol::Icmp, "ICMP");
                        ui.selectable_value(&mut self.protocol, Protocol::Raw, "Raw");
                    });
                ui.end_row();
                
                ui.label("Payload:");
                ui.text_edit_multiline(&mut self.payload);
                ui.end_row();
                
                ui.label("Packet Count:");
                ui.add(egui::DragValue::new(&mut self.count).clamp_range(1..=1000));
                ui.end_row();
                
                ui.label("Delay (ms):");
                ui.add(egui::DragValue::new(&mut self.delay).clamp_range(1..=5000));
                ui.end_row();
            });
        
        ui.separator();
        
        if ui.button("Craft and Send").clicked() && !self.crafting {
            self.start_crafting();
        }
        
        ui.separator();
        
        egui::ScrollArea::vertical().show(ui, |ui| {
            for result in &self.results {
                ui.label(result);
            }
        });
    }
    
    fn start_crafting(&mut self) {
        self.crafting = true;
        self.results.clear();
        
        let source_ip = self.source_ip.parse::<Ipv4Addr>().unwrap_or_else(|_| {
            Ipv4Addr::new(192, 168, 1, 100)
        });
        
        let dest_ip = self.dest_ip.parse::<Ipv4Addr>().unwrap_or_else(|_| {
            Ipv4Addr::new(192, 168, 1, 1)
        });
        
        let mut crafter = NativeCrafter::new(
            source_ip,
            dest_ip,
            self.source_port,
            self.dest_port,
            self.protocol.clone(),
            self.payload.clone(),
            self.count,
            self.delay,
        );
        
        crafter.craft_and_send();
        
        for i in 0..self.count {
            self.results.push(format!(
                "Sent {} packet to {}:{} - Protocol: {:?}",
                i + 1,
                self.dest_ip,
                self.dest_port,
                self.protocol
            ));
        }
        
        self.crafting = false;
    }
}
