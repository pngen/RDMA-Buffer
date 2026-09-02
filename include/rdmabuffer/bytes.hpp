// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Bounded, deterministic binary writer/reader. All de/serialization in the
// runtime is bounds-checked and explicit; there is no unchecked pointer math.

#pragma once

#include "crc32.hpp"

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rdmabuffer {
namespace bytes {

class Writer {
public:
    void u8(std::uint8_t v) { buf_.push_back(v); }
    void u32(std::uint32_t v) {
        for (int i = 0; i < 4; ++i) buf_.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    }
    void u64(std::uint64_t v) {
        for (int i = 0; i < 8; ++i) buf_.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    }
    void i64(std::int64_t v) { u64(static_cast<std::uint64_t>(v)); }
    void f64(double v) { std::memcpy(&tmp_[0], &v, 8); u64(tmp8()); }
    void str(std::string_view s) {
        u64(static_cast<std::uint64_t>(s.size()));
        for (char c : s) buf_.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(c)));
    }
    void raw(std::span<const std::uint8_t> b) {
        for (auto x : b) buf_.push_back(x);
    }
    const std::vector<std::uint8_t>& bytes() const { return buf_; }
    std::vector<std::uint8_t> take() { return std::move(buf_); }

private:
    std::uint64_t tmp8() const {
        std::uint64_t v = 0;
        std::memcpy(&v, &tmp_[0], 8);
        return v;
    }
    unsigned char tmp_[8]{};
    std::vector<std::uint8_t> buf_;
};

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> data) : data_(data), pos_(0) {}

    bool ok() const noexcept { return !error_; }

    bool u8(std::uint8_t& v) {
        if (remaining() < 1) return fail();
        v = data_[pos_++];
        return true;
    }
    bool u32(std::uint32_t& v) {
        if (remaining() < 4) return fail();
        v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<std::uint32_t>(data_[pos_++]) << (8 * i);
        return true;
    }
    bool u64(std::uint64_t& v) {
        if (remaining() < 8) return fail();
        v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(data_[pos_++]) << (8 * i);
        return true;
    }
    bool str(std::string& s, std::size_t max_len = (1u << 20)) {
        std::uint64_t n = 0;
        if (!u64(n)) return false;
        if (n > max_len || n > remaining()) return fail();
        s.assign(reinterpret_cast<const char*>(data_.data() + pos_), static_cast<std::size_t>(n));
        pos_ += static_cast<std::size_t>(n);
        return true;
    }
    bool raw(std::span<const std::uint8_t>& out, std::size_t len) {
        if (len > remaining()) return fail();
        out = data_.subspan(pos_, len);
        pos_ += len;
        return true;
    }
    bool skip_bytes(std::size_t len) {
        if (len > remaining()) return fail();
        pos_ += len;
        return true;
    }
    std::size_t remaining() const noexcept { return data_.size() - pos_; }
    std::size_t pos() const noexcept { return pos_; }

private:
    bool fail() {
        error_ = true;
        return false;
    }
    std::span<const std::uint8_t> data_;
    std::size_t pos_{0};
    bool error_{false};
};

} // namespace bytes
} // namespace rdmabuffer
