/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.authenticode;

import java.io.IOException;
import java.util.HashMap;
import net.jsign.CatalogFile;
import net.jsign.bouncycastle.cms.CMSException;
import org.apache.commons.codec.binary.Hex;
import org.openide.util.Exceptions;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.TagsManager;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.TagName;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskData;

/**
 *
 * @author root
 */
public class AuthentiCodeHelper {

    private static HashMap<String, TagName> tagMap = new HashMap<>();
    private static TagsManager tagsManager = Case.getCurrentCase().getServices().getTagsManager();

    static CatalogFile getCataLogFile(AbstractFile abstractFile) throws TskCoreException, IOException, CMSException {
        byte[] fileContent = getContent(abstractFile);
        CatalogFile cataLogFile = new CatalogFile(fileContent);
        return cataLogFile;
    }

    static boolean isRealFile(Content content) {
        if ((content instanceof AbstractFile)) {
            AbstractFile aFile = ((AbstractFile) content);
            if (aFile.isDirNameFlagSet(TskData.TSK_FS_NAME_FLAG_ENUM.UNALLOC)) {
                return false;
            }
            if (aFile.isDir()) {
                return false;
            }
            if (!aFile.canRead()) {
                return false;
            }

            if (aFile.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.ORPHAN)) {
                return false;
            }
        } else {
            return false;
        }

        return true;
    }

    static byte[] getContent(AbstractFile abstractFile) throws TskCoreException {
        byte[] fileContent = new byte[(int) abstractFile.getSize()];
        abstractFile.read(fileContent, 0, abstractFile.getSize());
        return fileContent;

    }

    static String getDigestString(byte[] d) {
        return new String(Hex.encodeHex(d));
    }

    public static synchronized TagName createOrGetTag(String tagNameString) {
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

    public static synchronized void addContentTag(Content file, TagName tag) throws TskCoreException {
        tagsManager.addContentTag(file, tag);
    }

    public static synchronized void addContentTag(Content file, TagName tag, String comment) throws TskCoreException {
        tagsManager.addContentTag(file, tag, comment);
    }

}
