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

    SleuthkitCase skCase;

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

        signerSubjectLabel = new javax.swing.JLabel();
        titleLabel = new javax.swing.JLabel();
        signatureLocationKeyLabel = new javax.swing.JLabel();
        signatureTypeLabel = new javax.swing.JLabel();
        signerSubjectKeyLabel = new javax.swing.JLabel();
        issuerSubjectKeyLabel = new javax.swing.JLabel();
        issuerSubjectLabel = new javax.swing.JLabel();
        validFromKeyLabel = new javax.swing.JLabel();
        validFromLabel = new javax.swing.JLabel();
        validUntilKeyLabel = new javax.swing.JLabel();
        validUntilLabel = new javax.swing.JLabel();

        org.openide.awt.Mnemonics.setLocalizedText(signerSubjectLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.signerSubjectLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(titleLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.titleLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(signatureLocationKeyLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.signatureLocationKeyLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(signatureTypeLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.signatureTypeLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(signerSubjectKeyLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.signerSubjectKeyLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(issuerSubjectKeyLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.issuerSubjectKeyLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(issuerSubjectLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.issuerSubjectLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(validFromKeyLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.validFromKeyLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(validFromLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.validFromLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(validUntilKeyLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.validUntilKeyLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(validUntilLabel, org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.validUntilLabel.text")); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(titleLabel)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(signatureLocationKeyLabel)
                            .addComponent(signerSubjectKeyLabel)
                            .addComponent(issuerSubjectKeyLabel)
                            .addComponent(validFromKeyLabel)
                            .addComponent(validUntilKeyLabel))
                        .addGap(41, 41, 41)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(validUntilLabel)
                            .addComponent(validFromLabel)
                            .addComponent(issuerSubjectLabel)
                            .addComponent(signerSubjectLabel)
                            .addComponent(signatureTypeLabel))))
                .addContainerGap(297, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(titleLabel)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(signatureLocationKeyLabel)
                    .addComponent(signatureTypeLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(signerSubjectLabel)
                    .addComponent(signerSubjectKeyLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(issuerSubjectKeyLabel)
                    .addComponent(issuerSubjectLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(validFromKeyLabel)
                    .addComponent(validFromLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(validUntilKeyLabel)
                    .addComponent(validUntilLabel))
                .addContainerGap(216, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel issuerSubjectKeyLabel;
    private javax.swing.JLabel issuerSubjectLabel;
    private javax.swing.JLabel signatureLocationKeyLabel;
    private javax.swing.JLabel signatureTypeLabel;
    private javax.swing.JLabel signerSubjectKeyLabel;
    private javax.swing.JLabel signerSubjectLabel;
    private javax.swing.JLabel titleLabel;
    private javax.swing.JLabel validFromKeyLabel;
    private javax.swing.JLabel validFromLabel;
    private javax.swing.JLabel validUntilKeyLabel;
    private javax.swing.JLabel validUntilLabel;
    // End of variables declaration//GEN-END:variables

    @Override
    public void setNode(Node selectedNode) {
        if (skCase == null) {
            skCase = Case.getCurrentCase().getSleuthkitCase();
        }
        AbstractFile abstractFile = selectedNode.getLookup().lookup(AbstractFile.class);
        if (abstractFile == null) {

        } else {
            X509CertificateHolder signerCert;
            try {
                signerCert = getSignerCert(abstractFile);
                drawSingerInformation(signerCert, abstractFile.getName());
            } catch (Exception ex) {
                signerSubjectLabel.setText(ex.getMessage());
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
        return org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.registerName");
    }

    @Override
    public String getToolTip() {
        return org.openide.util.NbBundle.getMessage(AuthentiCodeDataContentViewer.class, "AuthentiCodeDataContentViewer.toolTipp");
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
        signerSubjectLabel.setText(empty);
        issuerSubjectLabel.setText(empty);
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
        signerSubjectLabel.setText(cert.getSubject().toString());
        issuerSubjectLabel.setText(cert.getIssuer().toString());
        validFromLabel.setText(cert.getNotBefore().toString());
        validUntilLabel.setText(cert.getNotAfter().toString());
    }
}
