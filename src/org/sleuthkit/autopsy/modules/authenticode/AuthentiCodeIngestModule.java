/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.authenticode;

import java.io.IOException;
import net.jsign.PEVerifier;
import net.jsign.pe.PEFile;
import org.openide.util.Exceptions;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.TagsManager;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.TagName;
import org.sleuthkit.datamodel.TskCoreException;

/**
 *
 * @author root
 */
public class AuthentiCodeIngestModule implements FileIngestModule {

    private static final String tagNameString = "AuthentiCodeVerified";
    private TagsManager tagsManager;
    private TagName authentiCodeTag;

    private int errorcounter = 0;
    
    
    @Override
    public ProcessResult process(AbstractFile file) {
        try {
            if (file.getName().equals("putty.exe")) {
                PEInputAbstractFile faf = new PEInputAbstractFile(file);
                PEFile pef = new PEFile(faf);
                PEVerifier ver = new PEVerifier(pef);
                if (ver.isCorrectlySigned()) {
                    tagsManager.addContentTag(file, authentiCodeTag);
                }

            }
        } catch (NullPointerException | IOException | TskCoreException e) {
            //Exceptions.printStackTrace(e);
            errorcounter++;
        }
        return ProcessResult.OK;
    }

    @Override
    public void shutDown() {
        System.out.println("ErrorCounter: " + errorcounter);
    }

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        tagsManager = Case.getCurrentCase().getServices().getTagsManager();
        try {
            authentiCodeTag = tagsManager.addTagName(tagNameString, "All Files ending wiht .exe", TagName.HTML_COLOR.LIME);
        } catch (TagsManager.TagNameAlreadyExistsException ex) {
            try {
                for (TagName tagName : tagsManager.getAllTagNames()) {
                    if (tagName.getDisplayName().equals(tagNameString)) {
                        authentiCodeTag = tagName;
                        return;
                    }
                }
            } catch (TskCoreException ex1) {
                Exceptions.printStackTrace(ex1);
            }
        } catch (TskCoreException ex) {
            Exceptions.printStackTrace(ex);
        }
    }

}
