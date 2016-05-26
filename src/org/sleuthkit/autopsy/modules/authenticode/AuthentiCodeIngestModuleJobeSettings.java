/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.authenticode;

import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;

/**
 *
 * @author root
 */
public class AuthentiCodeIngestModuleJobeSettings implements IngestModuleIngestJobSettings{
    private static final long serialVersionUID = 6233551986933514335L;
    
    

    private boolean sha1Enabled = true;
    private boolean sha256Enabled = false;
    private boolean sha512Enabled = false;
            
    
    @Override
    public long getVersionNumber() {
           return 1;
    }
    
    
    /**
     * @return the sha1Enabled
     */
    public boolean isSha1Enabled() {
        return sha1Enabled;
    }

    /**
     * @param sha1Enabled the sha1Enabled to set
     */
    public void setSha1Enabled(boolean sha1Enabled) {
        this.sha1Enabled = sha1Enabled;
    }

    /**
     * @return the sha256Enabled
     */
    public boolean isSha256Enabled() {
        return sha256Enabled;
    }

    /**
     * @param sha256Enabled the sha256Enabled to set
     */
    public void setSha256Enabled(boolean sha256Enabled) {
        this.sha256Enabled = sha256Enabled;
    }

    /**
     * @return the sha512Enabled
     */
    public boolean isSha512Enabled() {
        return sha512Enabled;
    }

    /**
     * @param sha512Enabled the sha512Enabled to set
     */
    public void setSha512Enabled(boolean sha512Enabled) {
        this.sha512Enabled = sha512Enabled;
    }
    
}
