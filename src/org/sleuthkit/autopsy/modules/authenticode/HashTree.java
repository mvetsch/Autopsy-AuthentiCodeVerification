
package org.sleuthkit.autopsy.modules.authenticode;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javafx.util.Pair;

class HashTree {

    private final int depth = 2;

    private int level;
    private HashTree[] buckets;
    private List<Pair<ByteArray, Long>> hashes;

    public HashTree() {
        this(0);
    }

    private HashTree(int level) {
        this.level = level;

        if (level == depth) {
            this.hashes = new LinkedList<>();
        } else {
            this.buckets = new HashTree[256];
        }
    }

    public synchronized void add(byte[] s, long fileNumber) {
        if (isLeaf()) {
            hashes.add(new Pair<ByteArray, Long>(new ByteArray(s), fileNumber));
        } else {
            int b = s[level] & 0xff;
            if (buckets[b] == null) {
                buckets[b] = new HashTree(level + 1);
            }
            buckets[b].add(s, fileNumber);
        }
    }

    public Long get(byte[] hash) {
        if (isLeaf()) {
            return findInHashes(hash);
        } else if (buckets[0xFF & hash[level]] == null) {
            return null;
        } else {
            return buckets[0xFF & hash[level]].get(hash);
        }
    }

    private Long findInHashes(byte[] hash) {
        for (Pair<ByteArray, Long> s : hashes) {
            if (Arrays.equals(hash, s.getKey().getByteArray())) {
                return s.getValue();
            }
        }
        return null;
    }

    public int count() {
        if (isLeaf()) {
            return hashes.size();
        } else {
            int result = 0;
            for (HashTree h : buckets) {
                if (h != null) {
                    result += h.count();
                }
            }
            return result;
        }
    }

    private boolean isLeaf() {
        return level == depth;
    }

    void say() {
        if (isLeaf()) {
            System.out.println("\t\t\tLeaf HashCount:\t" + hashes.size());
        } else {
            for (int i = 0; i < 256; i++) {
                if (buckets[i] != null) {
                    printntabs(level);
                    System.out.print("Node:\t" + i + "\tcount:\t" + buckets[i].count());
                    System.out.print('\n');

                }
            }
            System.out.println("");
        }
    }

    private void printntabs(int n) {
        for (int i = 0; i < n; i++) {
            System.out.print('\t');
        }
    }

}

class ByteArray {

    private byte[] byteArray;

    public ByteArray(byte[] ba) {
        byteArray = ba;
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof ByteArray) {
            return Arrays.equals(getByteArray(), ((ByteArray) other).getByteArray());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return byteArray[2];
    }

    public byte[] getByteArray() {
        return byteArray;
    }
}
