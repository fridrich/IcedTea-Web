// Copyright (C) 2019 Karakun AG
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

package net.adoptopenjdk.icedteaweb.resources.downloader;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.jar.JarOutputStream;
import java.util.zip.GZIPInputStream;

/**
 * Unpacker for PACK200 and Gzip streams.
 * java.util.jar.Pack200 was removed in JDK 14, hence reflection.
 */
public class PackGzipUnpacker implements StreamUnpacker {

    private static final Method NEW_UNPACKER;
    private static final Method UNPACK;

    static {
        Method newUnpacker = null;
        Method unpack = null;
        try {
            newUnpacker = Class.forName("java.util.jar.Pack200").getMethod("newUnpacker");
            unpack = Class.forName("java.util.jar.Pack200$Unpacker").getMethod("unpack", InputStream.class, JarOutputStream.class);
        } catch (ReflectiveOperationException ignored) {
        }
        NEW_UNPACKER = newUnpacker;
        UNPACK = unpack;
    }

    public static boolean isSupported() {
        return UNPACK != null;
    }

    @Override
    public InputStream unpack(InputStream input) throws IOException {
        if (!isSupported()) {
            throw new IOException("pack200 is not supported by this JVM");
        }
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (final JarOutputStream outputStream = new JarOutputStream(buffer)) {
            UNPACK.invoke(NEW_UNPACKER.invoke(null), new GZIPInputStream(input), outputStream);
        } catch (IllegalAccessException e) {
            throw new IOException(e);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new IOException(e.getCause());
        }
        return new ByteArrayInputStream(buffer.toByteArray());
    }
}
