package com.dsingley.jwt.core;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import lombok.Builder;
import lombok.Getter;
import lombok.SneakyThrows;
import lombok.ToString;
import lombok.extern.jackson.Jacksonized;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;
import java.util.Base64;

@Builder
@Jacksonized
@Getter
@ToString
public class JwtPublicKey {
    private final String keyId;
    private final OffsetDateTime expiresAt;

    @JsonSerialize(using = RSAPublicKeySerializer.class)
    @JsonDeserialize(using = RSAPublicKeyDeserializer.class)
    @ToString.Exclude
    private final RSAPublicKey rsaPublicKey;

    private static class RSAPublicKeySerializer extends StdSerializer<RSAPublicKey> {
        private static final Base64.Encoder ENCODER = Base64.getEncoder();

        protected RSAPublicKeySerializer() {
            super(RSAPublicKey.class);
        }

        @Override
        @SneakyThrows
        public void serialize(RSAPublicKey value, JsonGenerator generator, SerializerProvider provider) {
            generator.writeString(ENCODER.encodeToString(value.getEncoded()));
        }
    }

    private static class RSAPublicKeyDeserializer extends StdDeserializer<RSAPublicKey> {
        private static final Base64.Decoder DECODER = Base64.getDecoder();
        private static final KeyFactory KEY_FACTORY = newKeyFactory();

        protected RSAPublicKeyDeserializer() {
            super(RSAPublicKey.class);
        }

        @Override
        @SneakyThrows
        public RSAPublicKey deserialize(JsonParser parser, DeserializationContext context) {
            byte[] bytes = DECODER.decode(parser.getValueAsString());
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bytes);
            return (RSAPublicKey) KEY_FACTORY.generatePublic(x509EncodedKeySpec);
        }

        @SneakyThrows
        private static KeyFactory newKeyFactory() {
            return KeyFactory.getInstance("RSA");
        }
    }
}
