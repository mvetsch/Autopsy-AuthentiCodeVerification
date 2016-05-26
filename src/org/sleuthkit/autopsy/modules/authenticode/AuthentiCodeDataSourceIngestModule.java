/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.authenticode;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import net.jsign.CatalogFile;
import net.jsign.SignedHashInfo;
import net.jsign.bouncycastle.asn1.x500.RDN;
import net.jsign.bouncycastle.cms.CMSException;
import org.openide.util.Exceptions;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.TagsManager;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TagName;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskData;

class AuthentiCodeDataSourceIngestModule implements DataSourceIngestModule {

    private SleuthkitCase skCase;
    private final AuthentiCodeIngestModuleJobeSettings settings;

    private void tagContentasUnsigned(Content content) {
        try {
            tagsManager.addContentTag(content, createOrGetTag("Unsigned Files"), "No Signature found for this content");
        } catch (TskCoreException ex) {
            Exceptions.printStackTrace(ex);
        }
    }

    enum HashType {
        SHA1, SHA256, SHA512
    };

    private LinkedList<Content> catalogFiles;
    private LinkedList<CatalogFile> parsedCatalogFiles;
    private HashTree hashTree = new HashTree();
    ;
    private HashMap<Long, List<Content>> matchedFileIds = new HashMap<>();

    HashMap<Long, MessageDigest> sha256digestInstances;
    volatile int hashedFilesCounter;

    HashMap<String, TagName> tagMap = new HashMap<>();

    TagsManager tagsManager = Case.getCurrentCase().getServices().getTagsManager();

    public AuthentiCodeDataSourceIngestModule(AuthentiCodeIngestModuleJobeSettings settings) {
        this.settings = settings;
    }

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        skCase = Case.getCurrentCase().getSleuthkitCase();
        catalogFiles = new LinkedList<>();
        parsedCatalogFiles = new LinkedList<>();

        sha256digestInstances = new HashMap<>();

    }

    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress progressBar) {
        try {
            progressBar.progress("searching for catalog files");
            traverseRecursive(dataSource);

            readCatalogFiles(catalogFiles, progressBar);
            hashTree.say();
            catalogFiles = null;

            int c = hashTree.count();
            System.out.println(c);

            progressBar.progress("compute SHA-256 hashes");
            progressBar.switchToIndeterminate();
            hashTheContent(dataSource, progressBar);

            c = matchedFileIds.size();
            System.out.println(c);

            System.out.println("done");
        } catch (TskCoreException ex) {
            Exceptions.printStackTrace(ex);
            return ProcessResult.ERROR;
        }

        return ProcessResult.OK;
    }

    private void traverseRecursive(Content content) throws TskCoreException {
        if (content.hasChildren()) {
            for (Content c : content.getChildren()) {
                traverseRecursive(c);
            }
        } else if (content instanceof AbstractFile) {
            if (((AbstractFile) content).getNameExtension().equals("cat")) {
                if (AuthentiCodeHelper.isRealFile(content)) {
                    catalogFiles.add(content);
                }
            }
        } else {
            System.out.println("was denn sonst?");
        }

    }

    private void introduceCatalogFile(Content content) {

        try {
            CatalogFile cataLogFile = AuthentiCodeHelper.getCataLogFile((AbstractFile) content);
            for (SignedHashInfo signedHashInfo : cataLogFile.getHashInfos()) {
                if (signedHashInfo.getHashbytes() != null) {
                    synchronized (hashTree) {
                        hashTree.add(signedHashInfo.getHashbytes(), content.getId());
                    }
                }
            }
            System.out.println(hashTree.count());
        } catch (TskCoreException | IOException | CMSException ex) {
            Exceptions.printStackTrace(ex);
        }

    }

    private void readCatalogFiles(LinkedList<Content> catalogFiles, DataSourceIngestModuleProgress progressBar) {
        progressBar.switchToIndeterminate();
        progressBar.progress("Reading catalog files");
        for (Content catalogFile : catalogFiles) {
            try {
                introduceCatalogFile(catalogFile);
            } catch (NullPointerException e) {
                e.printStackTrace();
            }
        }
    }

    ForkJoinPool hashTaskThreadPool = new ForkJoinPool();

    private void hashTheContent(Content content, DataSourceIngestModuleProgress progressBar) {
        hashTheContentRec(content);
        int amountOfTasks = hashTaskThreadPool.getQueuedSubmissionCount();
        progressBar.switchToDeterminate(amountOfTasks);

        hashTaskThreadPool.shutdown();
        try {
            while (!hashTaskThreadPool.awaitTermination(10, TimeUnit.SECONDS)) {
                progressBar.progress(amountOfTasks - hashTaskThreadPool.getQueuedSubmissionCount());
                progressBar.progress("Compute SHA Hashes");
            }

        } catch (InterruptedException ex) {
            Exceptions.printStackTrace(ex);
        }

        progressBar.switchToIndeterminate();
        progressBar.progress("tag Files with PublishersName");
        tagMatchedFiles();

    }

    private void tagMatchedFiles() {
        matchedFileIds.keySet().stream().forEach(catalogId -> {
            try {
                AbstractFile abstractCatalogFile = skCase.getAbstractFileById(catalogId);
                CatalogFile catalogFile = AuthentiCodeHelper.getCataLogFile(abstractCatalogFile);
                String catalogFileName = abstractCatalogFile.getName();
                String subject = catalogFile.getCert().getSubject().toString();
                RDN[] x = catalogFile.getCert().getSubject().getRDNs();

                TagName tagName = createOrGetTag(subject);

                List<Content> clist = matchedFileIds.get(catalogId);
                clist.stream().forEach(targetFile -> {
                    try {
                        tagsManager.addContentTag(targetFile, tagName, "Signed by " + catalogFileName + " #" + catalogId);
                    } catch (TskCoreException ex) {
                        Exceptions.printStackTrace(ex);
                    }
                });

            } catch (TskCoreException ex) {
                Exceptions.printStackTrace(ex);
            } catch (IOException ex) {
                Exceptions.printStackTrace(ex);
            } catch (CMSException ex) {
                Exceptions.printStackTrace(ex);
            }
        });
    }

    private void hashTheContentRec(Content content) {
        if (AuthentiCodeHelper.isRealFile(content)) {

            hashTaskThreadPool.submit(() -> {
                byte[] hash;
                try {
                    hash = computeHash(content);
                    hashedFilesCounter++;
                } catch (TskCoreException e) {
                    return;
                }
                Long catalogId = isTheHashKnownFromCatalogFile(hash);
                if (catalogId == null) {
                    //tagContentasUnsigned(content);
                    return;
                }
                saveMatch(catalogId, content);
            });
        }
        try {
            for (Content c : content.getChildren()) {
                hashTheContentRec(c);
            }
        } catch (TskCoreException e) {
            System.err.print(e);
        }

    }

    private void saveMatch(Long catalogId, Content content) {
        synchronized (matchedFileIds) {
            if (!matchedFileIds.containsKey(catalogId)) {
                matchedFileIds.put(catalogId, new LinkedList<>());
            }
            matchedFileIds.get(catalogId).add(content);
        }
        try {
            skCase.setKnown((AbstractFile) content, TskData.FileKnown.KNOWN);
        } catch (TskCoreException e) {
            System.out.println(e);
        }
    }

    private byte[] computeHash(Content content) throws TskCoreException {
        long threadId = Thread.currentThread().getId();
        if (sha256digestInstances.get(threadId) == null) {
            try {
                sha256digestInstances.put(threadId, MessageDigest.getInstance("SHA-256"));
            } catch (NoSuchAlgorithmException ex) {
                // does not happen
            }
        }
        MessageDigest sha256digest = sha256digestInstances.get(threadId);
        sha256digest.reset();
        sha256digest.update(AuthentiCodeHelper.getContent((AbstractFile) content));
        hashedFilesCounter++;
        byte[] d = sha256digest.digest();
        BlackboardAttribute a;
        a = new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_HASH_SHA2_256, "authentiCode", AuthentiCodeHelper.getDigestString(d));
        AbstractFile af = ((AbstractFile) content);
        //some blackboard magic

        return d;
    }

    private Long isTheHashKnownFromCatalogFile(byte[] hash) {
        return hashTree.get(hash);
    }

    private TagName createOrGetTag(String tagNameString) {
        if (tagMap.containsKey(tagNameString)) {
            return tagMap.get(tagNameString);

        }

        TagName newTag = null;
        try {
            newTag = tagsManager.addTagName(tagNameString, "Kind of AuthentiCode TagName", TagName.HTML_COLOR.AQUA);
        } catch (TagsManager.TagNameAlreadyExistsException ex) {
            try {
                for (TagName tagName : tagsManager.getAllTagNames()) {
                    if (tagName.getDisplayName().equals(tagNameString)) {
                        newTag = tagName;
                        break;
                    }
                }
            } catch (TskCoreException ex1) {
                Exceptions.printStackTrace(ex1);
            }
        } catch (TskCoreException ex) {
            Exceptions.printStackTrace(ex);
        }

        tagMap.put(tagNameString, newTag);
        return newTag;
    }
}
