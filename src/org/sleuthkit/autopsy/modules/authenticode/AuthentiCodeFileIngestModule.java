/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.authenticode;

import java.io.IOException;
import net.jsign.PEVerifier;
import net.jsign.pe.PEFile;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.TagName;
import org.sleuthkit.datamodel.TskCoreException;

public class AuthentiCodeFileIngestModule implements FileIngestModule {

    @Override
    public ProcessResult process(AbstractFile file) {
        try {

            if (isVerifiableFile(file)) {
                PEInputAbstractFile faf = new PEInputAbstractFile(file);
                PEFile pef = new PEFile(faf);
                PEVerifier ver = new PEVerifier(pef);
                if (ver.isCorrectlySigned()) {
                    String subject = ver.getCert().getSubject().toString();
                    TagName authentiCodeTag = AuthentiCodeHelper.createOrGetTag(subject);
                    AuthentiCodeHelper.addContentTag(file, authentiCodeTag, "Embedded Signature");
                }

            }
        } catch (NullPointerException | IOException | TskCoreException e) {
            return ProcessResult.ERROR;
        }
        return ProcessResult.OK;
    }

    @Override
    public void shutDown() {
    }

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
    }

    private boolean isVerifiableFile(AbstractFile file) {
        return file.isFile() && file.canRead();
    }

}
