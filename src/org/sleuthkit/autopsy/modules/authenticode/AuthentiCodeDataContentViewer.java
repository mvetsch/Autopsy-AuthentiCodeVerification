/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.modules.authenticode;

import java.awt.Component;
import java.io.IOException;
import java.util.List;
import net.jsign.CatalogFile;
import net.jsign.PEVerifier;
import net.jsign.bouncycastle.cert.X509CertificateHolder;
import net.jsign.bouncycastle.cms.CMSException;
import net.jsign.pe.PEFile;
import org.openide.nodes.Node;
import org.openide.util.Exceptions;
import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.corecomponentinterfaces.DataContentViewer;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.ContentTag;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;

@ServiceProvider(service = DataContentViewer.class)
public class AuthentiCodeDataContentViewer extends javax.swing.JPanel implements DataContentViewer {

    SleuthkitCase skCase = Case.getCurrentCase().getSleuthkitCase();

    public AuthentiCodeDataContentViewer() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        signerSubjectlabel = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        signatureTypeLabel = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        issuerSubjectlabel = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        validFromLabel = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        validUntilLabel = new javax.swing.JLabel();

        org.openide.awt.Mnemonics.setLocalizedText(signerSubjectlabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.signerSubjectlabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(jLabel1, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.jLabel1.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(jLabel2, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.jLabel2.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(signatureTypeLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.signatureTypeLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(jLabel4, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.jLabel4.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(jLabel5, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.jLabel5.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(issuerSubjectlabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.issuerSubjectlabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(jLabel7, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.jLabel7.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(validFromLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.validFromLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(jLabel9, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.jLabel9.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(validUntilLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.validUntilLabel.text")); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel1)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2)
                            .addComponent(jLabel4)
                            .addComponent(jLabel5)
                            .addComponent(jLabel7)
                            .addComponent(jLabel9))
                        .addGap(41, 41, 41)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(validUntilLabel)
                            .addComponent(validFromLabel)
                            .addComponent(issuerSubjectlabel)
                            .addComponent(signerSubjectlabel)
                            .addComponent(signatureTypeLabel))))
                .addContainerGap(297, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(signatureTypeLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(signerSubjectlabel)
                    .addComponent(jLabel4))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5)
                    .addComponent(issuerSubjectlabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel7)
                    .addComponent(validFromLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel9)
                    .addComponent(validUntilLabel))
                .addContainerGap(216, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel issuerSubjectlabel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JLabel signatureTypeLabel;
    private javax.swing.JLabel signerSubjectlabel;
    private javax.swing.JLabel validFromLabel;
    private javax.swing.JLabel validUntilLabel;
    // End of variables declaration//GEN-END:variables

    @Override
    public void setNode(Node selectedNode) {
        AbstractFile abstractFile = selectedNode.getLookup().lookup(AbstractFile.class);
        if (abstractFile == null) {

        } else {
            X509CertificateHolder signerCert;
            try {
                signerCert = getSignerCert(abstractFile);
                drawSingerInformation(signerCert, abstractFile.getName());
            } catch (Exception ex) {
                signerSubjectlabel.setText(ex.getMessage());
            }
        }
    }

    private X509CertificateHolder getSignerCert(AbstractFile abstractFile) throws Exception {
        try {

            List<ContentTag> contenttags = skCase.getContentTagsByContent(abstractFile);
            for (ContentTag tag : contenttags) {
                if (tag.getName().getDescription().equals("Kind of AuthentiCode TagName")) {
                    String tagComment = tag.getComment();
                    if (tagComment.matches(".*#[0-9]*")) {
                        return getCatalogFileCert(tag);
                    } else {
                        return new PEVerifier(new PEFile(new PEInputAbstractFile(abstractFile))).getCert();
                    }
                }
            }
        } catch (TskCoreException | IOException | CMSException ex) {
            Exceptions.printStackTrace(ex);
        }
        throw new Exception("no signer cert found");
    }

    private X509CertificateHolder getCatalogFileCert(ContentTag tag) throws CMSException, TskCoreException, NumberFormatException, IOException {
        int ni = tag.getComment().lastIndexOf('#') + 1;
        String ns = tag.getComment().substring(ni);
        Long catalogFileId = Long.parseLong(ns);
        AbstractFile abstractCatalogFile = skCase.getAbstractFileById(catalogFileId);
        CatalogFile catFile = AuthentiCodeHelper.getCataLogFile(abstractCatalogFile);
        return catFile.getCert();
    }

    @Override
    public String getTitle() {
        return "AuthentiCode";
    }

    @Override
    public String getToolTip() {
        return "mein ToolTipp";
    }

    @Override
    public DataContentViewer createInstance() {
        return new AuthentiCodeDataContentViewer();
    }

    @Override
    public Component getComponent() {
        return this;
    }

    @Override
    public void resetComponent() {
        String empty = "No signature found";
        signatureTypeLabel.setText(empty);
        signerSubjectlabel.setText(empty);
        issuerSubjectlabel.setText(empty);
        validFromLabel.setText(empty);
        validUntilLabel.setText(empty);

    }

    @Override
    public boolean isSupported(Node node) {
        AbstractFile a = node.getLookup().lookup(AbstractFile.class);
        return a != null && (!a.isDir()) && a.isFile();
    }

    @Override
    public int isPreferred(Node node) {
        return 8;
    }

    private void drawSingerInformation(X509CertificateHolder cert, String fileName) {
        signatureTypeLabel.setText(fileName);
        signerSubjectlabel.setText(cert.getSubject().toString());
        issuerSubjectlabel.setText(cert.getIssuer().toString());
        validFromLabel.setText(cert.getNotBefore().toString());
        validUntilLabel.setText(cert.getNotAfter().toString());
    }
}
