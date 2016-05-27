package org.sleuthkit.autopsy.modules.authenticode;

import java.io.EOFException;
import java.io.IOException;
import net.jsign.pe.PEInput;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.TskCoreException;

public class PEInputAbstractFile implements PEInput {

    private final AbstractFile file;
    private long seekPosition = 0;

    public PEInputAbstractFile(AbstractFile file) {
        this.file = file;
    }

    @Override
    public int read(byte[] bytes) throws IOException {
        try {
            int count = file.read(bytes, seekPosition, bytes.length);
            this.seekPosition += count;
            return count;

        } catch (TskCoreException ex) {
            throw new IOException();
        }
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        try {
            int count = file.read(bytes, seekPosition + offset, length);
            this.seekPosition += count;
            return count;
        } catch (TskCoreException ex) {
            throw new IOException();
        }
    }

    @Override
    public int read() throws IOException {
        byte[] buffer = new byte[1];
        try {
            if (file.read(buffer, seekPosition, 1) != 1) {
                return -1;
            }
            this.seekPosition++;

            return buffer[0] & 0xFF;
        } catch (TskCoreException ex) {
            throw new IOException();
        }
    }

    @Override
    public void seek(long offset) throws IOException {
        this.seekPosition = offset;
    }

    @Override
    public int readWord() throws IOException {
        int ch1 = this.read();
        int ch2 = this.read();
        if ((ch1 | ch2) < 0) {
            throw new EOFException();
        }
        return 0xffff & (ch1) + (ch2 << 8);
    }

    @Override
    public long readDWord() throws IOException {
        int ch1 = this.read();
        int ch2 = this.read();
        int ch3 = this.read();
        int ch4 = this.read();
        if ((ch1 | ch2 | ch3 | ch4) < 0) {
            throw new EOFException();
        }
        return 0xffffffffL & (ch1 + (ch2 << 8) + (ch3 << 16) + (ch4 << 24));
    }

    @Override
    public long readQWord() throws IOException {
        long ch1 = this.read();
        long ch2 = this.read();
        long ch3 = this.read();
        long ch4 = this.read();
        long ch5 = this.read();
        long ch6 = this.read();
        long ch7 = this.read();
        long ch8 = this.read();
        if ((ch1 | ch2 | ch3 | ch4) < 0) {
            throw new EOFException();
        }
        return ch1 + (ch2 << 8) + (ch3 << 16) + (ch4 << 24) + (ch5 << 32) + (ch6 << 40) + (ch7 << 48) + (ch8 << 56);
    }

    @Override
    public void close() throws IOException {

    }

    @Override
    public void write(byte[] bytes) throws IOException {
        throw new UnsupportedOperationException("Write to file not supported");
    }

    @Override
    public void writeByte(int i) throws IOException {
        throw new UnsupportedOperationException("Write to file not supported");
    }

    @Override
    public long length() {
        return file.getSize();
    }

    @Override
    public String getName() {
        return file.getName();
    }

    @Override
    public long lastModified() {
        return file.getMtime();
    }

}
