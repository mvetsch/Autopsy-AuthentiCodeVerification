/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.authenticode;

import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

/**
 *
 * @author root
 */
@ServiceProvider(service = IngestModuleFactory.class)
public class AuthentiCodeIngestModuleFactory implements IngestModuleFactory {

    @Override
    public String getModuleDisplayName() {
        return "AuthentiCode";
    }

    @Override
    public String getModuleDescription() {
        return "Verifies AuthentiCode signatures on Windows binaries";
    }

    @Override
    public String getModuleVersionNumber() {
		return "1.0.0";
    }

    @Override
    public boolean hasGlobalSettingsPanel() {
        return false;
    }

    @Override
    public IngestModuleGlobalSettingsPanel getGlobalSettingsPanel() {
        return new AuthentiCodeGlobalSettingsPanel();
    }

    @Override
    public IngestModuleIngestJobSettings getDefaultIngestJobSettings() {
           return new AuthentiCodeIngestModuleJobeSettings();
    }

    @Override
    public boolean hasIngestJobSettingsPanel() {
        return true;
    }

    @Override
    public IngestModuleIngestJobSettingsPanel getIngestJobSettingsPanel(IngestModuleIngestJobSettings settings) {
        return new AuthentiCodeJobSettingsPanel((AuthentiCodeIngestModuleJobeSettings) settings);
    }

    @Override
    public boolean isDataSourceIngestModuleFactory() {
        return true;
    }

    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings settings) {
        return new AuthentiCodeDataSourceIngestModule((AuthentiCodeIngestModuleJobeSettings) settings);
    }

    @Override
    public boolean isFileIngestModuleFactory() {
        return false;// true;
    }

    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings settings) {
        return new AuthentiCodeIngestModule();
    }

    
}
