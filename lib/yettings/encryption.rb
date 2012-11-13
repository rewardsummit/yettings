require 'base64'

module Yettings
  module Encryption
    extend ActiveSupport::Concern

    module ClassMethods
      def decrypt_string(encrypted)
        if key_and_iv_exists?
          decipher = OpenSSL::Cipher::AES.new(256, :CBC)
          decipher.decrypt
          decipher.key = key
          decipher.iv = iv
          encrypted = Base64.strict_decode64(encrypted)
          plain = decipher.update(encrypted) + decipher.final
        else
          "access denied (no key file and/or IV file found)"
        end
      end

      def encrypt_string(data)
        cipher = OpenSSL::Cipher::AES.new(256, :CBC)
        cipher.encrypt
        cipher.key = key
        cipher.iv = iv
        encrypted = cipher.update(data) + cipher.final
        encrypted = Base64.strict_encode64(encrypted)
      end

      def encrypt_file(private_file)
        return unless key_and_iv_exists? # Don't overwrite encrypted file without key
        public_file = public_path(private_file)
        public_yml = encrypt_string File.read(private_file)
        return unless check_overwrite(public_file, private_file, public_yml)
        File.open(public_file, 'w') { |f| f.write public_yml }
      end

      def encrypt_files!
        find_private_yml_files.each do |yml_file|
          encrypt_file yml_file
        end
      end

      def decrypt_file(public_file)
        private_file = private_path(public_file)
        private_yml = decrypt_string File.read(public_file)
        return unless check_overwrite(private_file, public_file, private_yml)
        File.open(private_file, 'w') { |f| f.write private_yml }
      end

      def decrypt_files!
        find_public_yml_files.each do |yml_file|
          decrypt_file yml_file
        end
      end

      def private_path(path)
        path.gsub(/^#{root}/, "#{private_root}").gsub(/.pub$/, "")
      end

      def public_path(path)
        path.gsub(/^#{private_root}/, root) + '.pub'
      end

      def check_overwrite(dest, source, content)
        unless File.exists?(dest)
          STDERR.puts "WARNING: creating #{dest} with contents of #{source}"
          FileUtils.mkpath File.dirname(dest)
          return true
        end
        return false if File.read(dest) == content
        if File.mtime(source) > File.mtime(dest)
          STDERR.puts "WARNING: overwriting #{dest} with contents of #{source}"
          true
        else
          false
        end
      end

      def key_and_iv_exists?
        File.exists?(key_path) && File.exists?(iv_path)
      end

      def key_path
        ENV["YETTINGS_KEY"] || "#{root}/.key"
      end

      def iv_path
        ENV["YETTINGS_IV"] || "#{root}/.iv"
      end

      def key
        file = File.open(key_path, "rb")
        b64_key = file.read
        file.close
        key = Base64.strict_decode64(b64_key)
      end

      def iv
        file = File.open(iv_path, "rb")
        b64_iv = file.read
        file.close
        iv = Base64.strict_decode64(b64_iv)
      end

      def gen_keys
        cipher = OpenSSL::Cipher::AES.new(256, :CBC)
        key = cipher.random_key
        b64_key = Base64.strict_encode64(key)
        iv = cipher.random_iv
        b64_iv = Base64.strict_encode64(iv)

        private_path = "#{root}/.private"
        FileUtils.mkpath private_path

        key_file = "#{root}/.key"
        File.open(key_file, 'w') { |f| f.write b64_key }

        iv_file = "#{root}/.iv"
        File.open(iv_file, 'w') { |f| f.write b64_iv }
      end
    end
  end
end
