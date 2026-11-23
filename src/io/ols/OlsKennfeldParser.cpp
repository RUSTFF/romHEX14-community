/*
 * This file is part of romHEX14.
 * Copyright (C) 2026 Cristian Tabuyo <contact@romhex14.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */


#include "OlsKennfeldParser.h"

#include <QHash>
#include <QRegularExpression>
#include <QSet>
#include <QStringDecoder>
#include <QtEndian>
#include <cmath>
#include <cstring>
#include <limits>

namespace ols {

static constexpr uint32_t DIM_A276_MAX  = 0x4000;
static constexpr uint32_t DIM_A396_MAX  = 0x400;
static constexpr uint32_t DIM_A400_MAX  = 0x1F400;

static int cellBitsToBytes(uint32_t cb)
{
    switch (cb) {
    case 2:  return 1;
    case 8:  return 1;
    case 10: return 2;
    case 16: return 2;
    case 32: return 4;
    default: return 2;
    }
}


uint32_t OlsKennfeldParser::peekU32(const QByteArray &data, qsizetype off)
{
    if (off < 0 || off + 4 > data.size()) return 0;
    return qFromLittleEndian<uint32_t>(
        reinterpret_cast<const uchar *>(data.constData() + off));
}

double OlsKennfeldParser::peekF64(const QByteArray &data, qsizetype off)
{
    if (off < 0 || off + 8 > data.size()) return std::numeric_limits<double>::quiet_NaN();
    uint64_t bits = qFromLittleEndian<uint64_t>(
        reinterpret_cast<const uchar *>(data.constData() + off));
    double v;
    std::memcpy(&v, &bits, sizeof(v));
    return v;
}


static QString decodeOlsString(const char *p, int len)
{
    if (len <= 0) return QString();
    QByteArray raw(p, len);
    bool allAscii = true;
    for (char c : raw) {
        if (static_cast<uint8_t>(c) >= 0x80) { allAscii = false; break; }
    }
    if (allAscii) return QString::fromLatin1(raw);

    QStringDecoder utf8(QStringDecoder::Utf8);
    QString asUtf8 = utf8(raw);
    if (!utf8.hasError() && !asUtf8.contains(QChar::ReplacementCharacter))
        return asUtf8;

    for (const char *enc : {"GB18030", "GBK", "Shift_JIS", "EUC-KR"}) {
        QStringDecoder dec(enc);
        if (!dec.isValid()) continue;
        QString s = dec(raw);
        if (!dec.hasError() && !s.contains(QChar::ReplacementCharacter))
            return s;
    }

    QStringDecoder cp1252("Windows-1252");
    if (cp1252.isValid()) return cp1252(raw);

    return QString::fromLatin1(raw);
}


bool OlsKennfeldParser::isText(const char *data, int length)
{
    if (length <= 0) return false;
    int printable = 0;
    for (int i = 0; i < length; ++i) {
        auto b = static_cast<uint8_t>(data[i]);
        if ((b >= 32 && b < 127) || b == 0x09 || b == 0x0A || b == 0x0D
            || b >= 0x80)
            ++printable;
    }
    return printable >= static_cast<int>(0.85 * length);
}

bool OlsKennfeldParser::isIdent(const QString &s)
{
    // Accept any printable map name that isn't obviously garbage.
    // Map names can contain Latin, CJK, Cyrillic, umlauts, dots,
    // brackets, hyphens, etc.  Reject only: empty, too long, or strings
    // that are mostly control/whitespace characters.
    if (s.isEmpty() || s.size() > 120) return false;

    int printable = 0;
    for (const QChar &ch : s) {
        if (ch.unicode() < 0x20 && ch != QLatin1Char('\t'))
            return false;   // control character = not a name
        if (!ch.isSpace())
            ++printable;
    }
    // Must have at least one non-whitespace character, and first char
    // must not be a digit (avoids matching stray numeric fields).
    return printable >= 1 && !s[0].isDigit();
}


OlsKennfeldParser::PStr OlsKennfeldParser::readCString(
    const QByteArray &data, qsizetype offset, int maxLen, int schema)
{
    PStr result;
    if (offset + 4 > data.size()) return result;

    int32_t slen = static_cast<int32_t>(peekU32(data, offset));

    if (schema >= 439) {
        if (slen == -1) {
            result.text = QStringLiteral("-");
            result.endOffset = offset + 4;
            return result;
        }
        if (slen == -2) {
            result.text = QStringLiteral("?");
            result.endOffset = offset + 4;
            return result;
        }
        if (slen == -3) {
            result.text = QStringLiteral("%");
            result.endOffset = offset + 4;
            return result;
        }
        if (slen <= 0) {
            result.text = QLatin1String("");
            result.endOffset = offset + 4;
            return result;
        }
        if (slen > maxLen) return result;
        if (offset + 4 + slen > data.size()) return result;
        const char *p = data.constData() + offset + 4;
        if (!isText(p, slen)) return result;
        result.text = decodeOlsString(p, slen);
        result.endOffset = offset + 4 + slen;
        return result;
    }

    if (slen < 0 || slen > maxLen) return result;
    uint32_t len = static_cast<uint32_t>(slen);
    if (len == 0) {
        result.text = QLatin1String("");
        result.endOffset = offset + 4;
        return result;
    }
    if (offset + 4 + static_cast<qsizetype>(len) + 1 > data.size())
        return result;
    const char *p = data.constData() + offset + 4;
    if (!isText(p, static_cast<int>(len))) return result;
    result.text = decodeOlsString(p, static_cast<int>(len));
    result.endOffset = offset + 4 + len + 1;
    return result;
}

struct CfrResult {
    QString name;
    qsizetype endOffset = -1;
    bool valid() const { return endOffset >= 0; }
};

static CfrResult readCFolderRef(const QByteArray &data, qsizetype offset,
                                int schema)
{
    CfrResult result;
    auto inner = OlsKennfeldParser::readCString(data, offset, 8192, schema);
    if (!inner.valid()) return result;
    result.name = inner.text;
    qsizetype o = inner.endOffset;
    if (schema < 330) {
        result.endOffset = o;
        return result;
    }
    if (schema >= 345) {
        if (o + 4 > data.size()) return result;
        o += 4;
    }
    if (schema >= 345) {
        if (o + 4 > data.size()) return result;
        o += 4;
    }
    if (o + 4 > data.size()) return result;
    uint32_t count = OlsKennfeldParser::peekU32(data, o);
    o += 4;
    if (count > 0x1000) {
        result.endOffset = inner.endOffset;
        return result;
    }
    if (schema >= 345 && count > 0) {
        for (uint32_t i = 0; i < count; ++i) {
            auto entry = OlsKennfeldParser::readCString(data, o, 8192, schema);
            if (!entry.valid()) return result;
            o = entry.endOffset;
            if (o + 4 > data.size()) return result;
            o += 4;
        }
    }
    result.endOffset = o;
    return result;
}

static const QSet<QString> &envelopeStrings()
{
    static const QSet<QString> s = {
        QStringLiteral("(DAMOS)"),
        QStringLiteral("OLS 5.0 (Windows)"),
        QStringLiteral("Hexdump"), QStringLiteral("My maps"),
        QStringLiteral("Original"),
        QStringLiteral("Passenger car"),
        QStringLiteral("Engine"),
        QStringLiteral("Binary data"),
        QStringLiteral("0 (Original)"),
        QStringLiteral("Version 1"),
    };
    return s;
}


struct Cursor {
    const QByteArray &buf;
    qsizetype off;
    qsizetype start;
    int schema = 288;

    Cursor(const QByteArray &b, qsizetype o, int sch = 288)
        : buf(b), off(o), start(o), schema(sch) {}

    qsizetype remain() const { return buf.size() - off; }

    // Reads past the end yield 0 instead of reading out of bounds; callers
    // already reject records whose fields come out implausible.
    uint8_t u8() {
        const uint8_t v = (off >= 0 && off < buf.size())
            ? static_cast<uint8_t>(buf.at(off)) : 0;
        off += 1;
        return v;
    }

    uint32_t u32() {
        auto v = OlsKennfeldParser::peekU32(buf, off);
        off += 4;
        return v;
    }

    double f64() {
        auto v = OlsKennfeldParser::peekF64(buf, off);
        off += 8;
        return v;
    }

    bool bool1() {
        return u8() != 0;
    }

    void skip(int n) { off += n; }

    OlsKennfeldParser::PStr cstr() {
        auto r = OlsKennfeldParser::readCString(buf, off, 8192, schema);
        if (r.valid())
            off = r.endOffset;
        return r;
    }

    CfrResult cfr() {
        auto r = readCFolderRef(buf, off, schema);
        if (r.valid())
            off = r.endOffset;
        return r;
    }
};


static QPair<int,int> classifyDims(uint32_t kennfeldType,
                                   uint32_t a276, uint32_t a280,
                                   uint32_t a396, uint32_t a400)
{
    if (a396 > DIM_A396_MAX) a396 = 0;
    if (a400 > DIM_A400_MAX) a400 = 0;
    if (a276 > DIM_A276_MAX) a276 = 0;

    if (kennfeldType == 1 || kennfeldType == 2) {
        return {1, 1};
    }
    if (kennfeldType == 3) {
        int x;
        if (a396 > 0) {
            x = static_cast<int>(a396);
        } else {
            x = static_cast<int>(qMax(a276, a280));
            if (x <= 0) x = 1;
        }
        return {x, 1};
    }
    if (kennfeldType == 5) {
        if (a400 > 0 || a396 > 0) {
            int x = (a400 > 0) ? static_cast<int>(a400) : 1;
            int y = (a396 > 0) ? static_cast<int>(a396) : 1;
            return {x, y};
        }
        int x = (a280 > 0) ? static_cast<int>(a280) : 1;
        int y = (a276 > 0) ? static_cast<int>(a276) : 1;
        return {x, y};
    }
    if (a400 > 0 && a396 > 0)
        return {static_cast<int>(a400), static_cast<int>(a396)};
    if (a280 > 0 || a276 > 0)
        return {qMax(static_cast<int>(a280), 1), qMax(static_cast<int>(a276), 1)};
    return {1, 1};
}


struct AxisResult {
    AxisInfo axis;
    qsizetype endOffset = -1;
    bool valid() const { return endOffset >= 0; }
};

static AxisResult readAxis(const QByteArray &buf, qsizetype axisStart,
                           int schema, int expectedSize)
{
    AxisResult result;
    if (axisStart + 4 > buf.size())
        return result;

    qsizetype o = axisStart;

    auto cfr = readCFolderRef(buf, o, schema);
    if (!cfr.valid()) return result;
    QString axisName = cfr.name;
    o = cfr.endOffset;

    auto r = OlsKennfeldParser::readCString(buf, o, 8192, schema);
    if (!r.valid()) return result;
    QString axisUnit = r.text;
    o = r.endOffset;

    if (o + 8 > buf.size()) return result;
    double scale = OlsKennfeldParser::peekF64(buf, o); o += 8;

    if (o + 8 > buf.size()) return result;
    double offsetV = OlsKennfeldParser::peekF64(buf, o); o += 8;

    if (o + 5 * 4 > buf.size()) return result;
    uint32_t axisType       = OlsKennfeldParser::peekU32(buf, o); o += 4;
    uint32_t axisRomAddress = OlsKennfeldParser::peekU32(buf, o); o += 4;
    uint32_t axisDataType   = OlsKennfeldParser::peekU32(buf, o); o += 4;
    o += 4;
    uint32_t cellBits       = OlsKennfeldParser::peekU32(buf, o); o += 4;

    if (cellBits != 2 && cellBits != 10 && cellBits != 16)
        cellBits = 10;

    if (o + 2 > buf.size()) return result;
    o += 2;

    if (schema >= 264) {
        if (o + 8 > buf.size()) return result;
        o += 8;
    }
    if (schema >= 241) {
        if (o + 4 > buf.size()) return result;
        o += 4;
    }
    if (schema >= 8) {
        if (o + 4 > buf.size()) return result;
        o += 4;
    }
    bool flag3 = false;
    if (schema >= 12) {
        if (o + 1 > buf.size()) return result;
        flag3 = (static_cast<uint8_t>(buf[o]) != 0);
        o += 1;
    }
    if (schema >= 73) {
        if (o + 4 > buf.size()) return result;
        uint32_t inlineCount = OlsKennfeldParser::peekU32(buf, o); o += 4;
        if (inlineCount > 0) {
            if (inlineCount > 0x10000 || o + static_cast<qsizetype>(inlineCount) > buf.size())
                return result;
            o += inlineCount;
        }
    }
    if (schema >= 77) {
        if (o + 4 > buf.size()) return result;
        o += 4;
    }
    uint32_t axisRomV2 = 0;
    if (schema >= 91) {
        if (o + 4 > buf.size()) return result;
        axisRomV2 = OlsKennfeldParser::peekU32(buf, o); o += 4;
    }
    if (schema >= 354) {
        r = OlsKennfeldParser::readCString(buf, o, 8192, schema);
        if (!r.valid()) return result;
        o = r.endOffset;
    }
    if (schema >= 372) {
        if (o + 4 > buf.size()) return result;
        uint32_t folderCount = OlsKennfeldParser::peekU32(buf, o);
        o += 4;
        if (folderCount > 0x1000) return result;
        for (uint32_t i = 0; i < folderCount; ++i) {
            auto fr = readCFolderRef(buf, o, schema);
            if (!fr.valid()) return result;
            o = fr.endOffset;
        }
    }
    if (schema >= 440) {
        if (o + 4 > buf.size()) return result;
        o += 4;
    }

    uint32_t romAddr = axisRomAddress;
    if (!romAddr || romAddr == 0xFFFFFFFF) {
        if (axisRomV2 && axisRomV2 != 0xFFFFFFFF)
            romAddr = axisRomV2;
        else
            romAddr = 0;
    }

    Q_UNUSED(axisType);

    auto bytesFromDataType = [](uint32_t dt) -> int {
        switch (dt) {
        case 2: case 3:                   return 2;
        case 4: case 5: case 6: case 7:   return 4;
        case 10: case 11: case 12: case 13: return 8;
        default: return 1;
        }
    };
    auto isBigEndianDataType = [](uint32_t dt) -> bool {
        return (dt == 2 || dt == 4 || dt == 6 || dt == 10 || dt == 12);
    };

    result.axis.inputName = axisName;
    result.axis.scaling.unit = axisUnit;
    result.axis.hasScaling = (scale != 1.0 || offsetV != 0.0);
    result.axis.scaling.type = CompuMethod::Type::Linear;
    result.axis.scaling.linA = scale;
    result.axis.scaling.linB = offsetV;
    result.axis.hasPtsAddress = (romAddr > 0 && romAddr != 0xFFFFFFFF);
    result.axis.ptsAddress = romAddr;
    result.axis.ptsCount = expectedSize;
    result.axis.ptsDataType = axisDataType;
    result.axis.ptsBigEndian = isBigEndianDataType(axisDataType);
    result.axis.ptsSigned = flag3;
    result.axis.ptsDataSize = (axisDataType > 0)
        ? bytesFromDataType(axisDataType)
        : cellBitsToBytes(cellBits);
    result.endOffset = o;
    return result;
}


MapInfo OlsKennfeldParser::parseOne(const QByteArray &data,
                                     qsizetype commentOffset,
                                     qsizetype hardLimit,
                                     int schema)
{
    MapInfo mi;
    Cursor c(data, commentOffset, schema);

    auto comment = c.cfr();
    if (!comment.valid()) return mi;
    if (envelopeStrings().contains(comment.name)) return mi;
    if (comment.name.startsWith(QStringLiteral("Imported from"))) return mi;
    if (!comment.name.isEmpty()
        && !isText(comment.name.toLatin1().constData(), comment.name.size()))
        return mi;

    if (c.remain() < 20) return mi;
    uint32_t kennfeldType  = c.u32();
    c.u32();
    uint32_t cellDataType  = c.u32();
    c.u32();
    uint32_t cellBits      = c.u32();
    if (cellBits != 2 && cellBits != 10 && cellBits != 16)
        cellBits = 10;

    QString name;
    if (schema >= 80) {
        if (c.remain() >= 12 && peekU32(data, c.off) == 0x0A000000) {
            c.skip(8);
        } else {
            c.u32();
        }
        auto n = c.cstr();
        if (!n.valid() || !isIdent(n.text)) return mi;
        name = n.text;
    } else {
        return mi;
    }

    if (schema >= 298) c.u32();
    if (schema >= 299) c.u32();
    if (schema >= 94)  c.u32();
    if (schema >= 74)  c.bool1();

    // Inner archive subtype defaults to 1; the gate-123 u32 fires for every .ols.
    if (schema >= 123)
        c.u32();

    if (schema >= 300) {
        for (int i = 0; i < 6; ++i) c.f64();
        if (schema >= 67) {
            for (int i = 0; i < 6; ++i) c.skip(8);
        }
    } else if (schema >= 67) {
        for (int i = 0; i < 6; ++i) c.skip(8);
    } else if (schema >= 66) {
        c.skip(16);
    } else if (schema < 59) {
        c.skip(8);
    }

    bool cellInverse = c.bool1();
    bool cellSigned  = c.bool1();
    c.bool1();
    c.bool1();
    Q_UNUSED(cellInverse);

    uint32_t a276 = c.u32();
    uint32_t a280 = c.u32();
    uint32_t a396 = c.u32();
    uint32_t a400 = c.u32();
    c.u32();

    auto [xSize, ySize] = classifyDims(kennfeldType, a276, a280, a396, a400);
    if (xSize <= 0 || ySize <= 0)
        return mi;
    // Reject obviously implausible dimensions early so the display layer
    // never sees a map it can't render.  ECU calibration maps top out well
    // below these limits in practice.
    if (xSize > 256 || ySize > 256 || (xSize * ySize) > 4096 * 4)
        return mi;

    auto label = c.cstr();
    auto unit  = c.cstr();
    if (!label.valid() || !unit.valid()) return mi;

    double scale  = c.f64();
    double offset = c.f64();
    uint32_t romAddress = c.u32();
    uint32_t romEnd     = c.u32();
    uint32_t universalBase = c.u32();  // a2+644 ("Base Address" / virtual flash end)

    QString physUnit = !unit.text.isEmpty() ? unit.text : label.text;

    if (schema >= 264) c.f64();
    if (schema >= 61)  c.u32();
    if (schema >= 105) {
        c.u32(); c.u32(); c.u32(); c.u32();
    }

    auto rowsAxisRes = readAxis(data, c.off, schema, ySize);
    if (!rowsAxisRes.valid()) return mi;
    c.off = rowsAxisRes.endOffset;

    auto colsAxisRes = readAxis(data, c.off, schema, xSize);
    if (!colsAxisRes.valid()) return mi;
    c.off = colsAxisRes.endOffset;
    qsizetype axesEnd = c.off;

    // Post-axis tail — walk version-gated fields in order.
    // On any failure fall back to the inter-record 01 01 01 trailer scan.
    bool tailOk = true;
    auto skip = [&](int n) {
        if (!tailOk) return;
        if (c.off + n > data.size()) { tailOk = false; return; }
        c.off += n;
    };
    auto cstr = [&]() {
        if (!tailOk) return;
        auto r = OlsKennfeldParser::readCString(data, c.off, 8192, schema);
        if (!r.valid()) { tailOk = false; return; }
        c.off = r.endOffset;
    };

    if (schema >= 58)  skip(1);
    if (schema >= 68)  skip(1);
    if (schema >= 90)  skip(4);
    if (schema >= 9)   skip(8);
    if (schema >= 49)  skip(4 + 1 + 1 + 8 + 8);
    if (schema >= 51)  skip(4);
    if (schema >= 53)  skip(1 + 8 + 8 + 8 + 4);
    if (schema >= 54)  skip(8);
    if (schema >= 55)  skip(3);
    if (schema >= 315) skip(4);
    if (schema >= 383) skip(4 + 16);
    if (schema >= 329) skip(4);
    if (schema >= 346) skip(8);
    if (schema >= 395) skip(4);
    QString postComment;
    if (tailOk && schema >= 476) {
        skip(4);
        if (tailOk && c.off + 4 <= data.size()) {
            uint32_t dwCount = peekU32(data, c.off); c.off += 4;
            if (dwCount <= 0x10000) skip(static_cast<int>(dwCount) * 4);
            else tailOk = false;
        } else tailOk = false;
        if (tailOk && c.off + 4 <= data.size()) {
            uint32_t strCount = peekU32(data, c.off); c.off += 4;
            if (strCount <= 0x10000) {
                for (uint32_t i = 0; i < strCount && tailOk; ++i) {
                    auto s = c.cstr();
                    if (s.valid() && !s.text.isEmpty()) {
                        if (s.text != name && s.text != comment.name) {
                            if (postComment.isEmpty() || s.text.size() > postComment.size())
                                postComment = s.text;
                        }
                    }
                }
            } else tailOk = false;
        } else tailOk = false;
    }
    if (schema >= 503) skip(4 + 8);
    if (schema >= 596) skip(4);

    qsizetype searchStart = tailOk ? c.off : axesEnd;
    qsizetype recordEnd = qMin(searchStart, hardLimit);
    {
        const char *d = data.constData();
        qsizetype searchEnd = qMin(hardLimit, searchStart + 0x800);
        for (qsizetype i = searchStart; i + 3 <= searchEnd; ++i) {
            if (static_cast<uint8_t>(d[i]) == 0x01
                && static_cast<uint8_t>(d[i+1]) == 0x01
                && static_cast<uint8_t>(d[i+2]) == 0x01) {
                recordEnd = i + 3;
                break;
            }
        }
    }

    if (!comment.name.isEmpty()) {
        mi.name = comment.name;
        mi.id   = name;
    } else {
        mi.name = name;
        mi.id   = name;
    }
    mi.description = postComment;
    mi.rawAddress = romAddress;
    mi.address = romAddress;
    mi.olsUniversalBase = universalBase;
    mi.dimensions = { xSize, ySize };

    auto bytesFromDataType = [](uint32_t dt) -> int {
        switch (dt) {
        case 2: case 3:                     return 2;
        case 4: case 5: case 6: case 7:     return 4;
        case 10: case 11: case 12: case 13: return 8;
        default: return 1;
        }
    };
    auto isBigEndianDataType = [](uint32_t dt) -> bool {
        return (dt == 2 || dt == 4 || dt == 6 || dt == 10 || dt == 12);
    };

    int derivedCellBytes;
    if (cellDataType != 0) {
        derivedCellBytes = bytesFromDataType(cellDataType);
    } else {
        derivedCellBytes = cellBitsToBytes(cellBits);
        if (romAddress > 0 && romEnd > romAddress && xSize > 0 && ySize > 0) {
            uint32_t dataBytes = romEnd - romAddress;
            int totalCells = xSize * ySize;
            if (totalCells > 0) {
                int computedSize = static_cast<int>(dataBytes) / totalCells;
                if (computedSize == 1 || computedSize == 2 || computedSize == 4)
                    derivedCellBytes = computedSize;
            }
        }
    }
    mi.dataSize       = derivedCellBytes;
    mi.cellDataType   = cellDataType;
    mi.cellBigEndian  = isBigEndianDataType(cellDataType);
    if (cellDataType != 0) {
        mi.dataSigned = cellSigned;
    } else {
        mi.dataSigned = (derivedCellBytes == 1 && cellBits == 10)
                        || (offset < 0);
    }
    mi.linkConfidence = 100;
    mi.columnMajor = false;

    if (xSize <= 1 && ySize <= 1)
        mi.type = QStringLiteral("VALUE");
    else if (ySize <= 1)
        mi.type = QStringLiteral("CURVE");
    else
        mi.type = QStringLiteral("MAP");

    if (scale != 0.0 && scale != 1.0) {
        mi.hasScaling = true;
        mi.scaling.type = CompuMethod::Type::Linear;
        mi.scaling.linA = scale;
        mi.scaling.linB = offset;
    } else if (offset != 0.0) {
        mi.hasScaling = true;
        mi.scaling.type = CompuMethod::Type::Linear;
        mi.scaling.linA = (scale != 0.0) ? scale : 1.0;
        mi.scaling.linB = offset;
    }
    if (!physUnit.isEmpty())
        mi.scaling.unit = physUnit;

    mi.xAxis = colsAxisRes.axis;
    if (ySize > 1)
        mi.yAxis = rowsAxisRes.axis;

    mi.length = static_cast<int>(recordEnd - commentOffset);

    return mi;
}


QVector<MapInfo> OlsKennfeldParser::parseAll(const QByteArray &data,
                                              qsizetype regionStart,
                                              qsizetype regionEnd,
                                              int schema,
                                              QStringList *warnings)
{
    Q_UNUSED(warnings);
    QVector<MapInfo> maps;
    if (schema >= 500) {
        static const int candidateSchemas[] = { 350, 300, 200, 100, 80, 1, 0 };
        for (int s : candidateSchemas) {
            MapInfo test = parseOne(data, regionStart, regionEnd, s);
            if (!test.name.isEmpty()) {
                schema = s;
                break;
            }
        }
    }

    qsizetype off = regionStart;
    while (off < regionEnd - 8) {
        MapInfo mi = parseOne(data, off, regionEnd, schema);
        if (!mi.name.isEmpty()) {
            qsizetype recordEnd = off + mi.length;
            {
                const int cells = qMax(1, mi.dimensions.x)
                                * qMax(1, mi.dimensions.y);
                mi.length = cells * qMax(1, mi.dataSize);
            }
            maps.append(mi);
            off = recordEnd;
            for (int skip = 0; skip < 64 && off < regionEnd; ++skip) {
                if (off + 4 > data.size()) break;
                uint32_t peek = peekU32(data, off);
                if (peek >= 4 && peek <= 200)
                    break;
                ++off;
            }
            continue;
        }
        ++off;
    }

    return maps;
}


QPair<qsizetype, qsizetype> OlsKennfeldParser::findMapRegion(
    const QByteArray &data, int schema)
{
    qsizetype end = data.size();

    char needle[4];
    qToLittleEndian<uint32_t>(0x98638811, reinterpret_cast<uchar *>(needle));
    qsizetype j = data.indexOf(QByteArray::fromRawData(needle, 4));
    if (j > 0x1000)
        end = j;

    qsizetype start = 0x180;
    qsizetype scanEnd = qMin(static_cast<qsizetype>(0x10000), end - 32);
    for (qsizetype off = 0x180; off < scanEnd; ++off) {
        if (off + 4 >= end) break;
        uint32_t L = peekU32(data, off);
        if (L >= 4 && L <= 200 && off + 4 + static_cast<qsizetype>(L) < end) {
            const char *p = data.constData() + off + 4;
            if (!isText(p, qMin(static_cast<int>(L), 32)))
                continue;
            MapInfo test = parseOne(data, off, end, schema);
            if (!test.name.isEmpty()) {
                start = off;
                break;
            }
        }
    }
    return {start, end};
}


QVector<MapInfo> OlsKennfeldParser::parseIntern(const QByteArray &internPayload,
                                                 int schema,
                                                 QStringList *warnings)
{
    if (internPayload.size() < 14) {
        if (warnings)
            warnings->append(OlsKennfeldParser::tr("intern payload too small (%1 bytes)")
                                 .arg(internPayload.size()));
        return {};
    }

    const uint32_t mapCount = peekU32(internPayload, 1);
    if (mapCount == 0 || mapCount > 100000) {
        if (warnings)
            warnings->append(OlsKennfeldParser::tr("intern payload map count %1 out of range")
                                 .arg(mapCount));
        return {};
    }

    QVector<MapInfo> maps;
    qsizetype off = 14;
    const auto sz = internPayload.size();

    while (off < sz - 8) {
        while (off < sz && static_cast<uint8_t>(internPayload.at(off)) == 0x00) ++off;
        if (off >= sz - 8) break;

        MapInfo mi = parseOne(internPayload, off, sz, schema);
        if (!mi.name.isEmpty()) {
            qsizetype recordEnd = off + mi.length;
            mi.length = 0;
            maps.append(mi);
            off = recordEnd;
            continue;
        }
        ++off;
    }

    return maps;
}



// ─── WinOLS 5 record layout ────────────────────────────────────────────────
//
// Offsets are relative to the first byte after the length-prefixed name
// (u32 len + len bytes, no terminator):
//   +0x14 u32  cell data type (1 u8, 2 u16 BE, 3 u16 LE, 4/5 u32, 6/7 float…)
//   +0x18 u32  bytes per cell
//   +0x9A u8   cell signed flag
//   +0x9D u32  column count (X)          +0xA1 u32  row count (Y)
// followed by optional strings and the data block
//   f64 factor, f64 offset, u32 romStart, u32 romEnd
// and two axis blocks (X first, then Y), each preceded by its optional
// name/unit strings and f64 factor, f64 offset:
//   u32 1, u32 romAddr, u32 dataType, u32 bytesPerPoint, u32 0x0A, …
//   +42 u8 signed flag
// Cell data is stored X-fastest (row by row).

namespace {

int v5BytesFromDataType(uint32_t dt)
{
    switch (dt) {
    case 1: case 8: case 9:             return 1;
    case 2: case 3:                     return 2;
    case 4: case 5: case 6: case 7:     return 4;
    case 10: case 11: case 12: case 13: return 8;
    default:                            return 0;
    }
}

bool v5IsBigEndian(uint32_t dt)
{
    return dt == 2 || dt == 4 || dt == 6 || dt == 10 || dt == 12;
}

bool v5Printable(const QByteArray &d, qsizetype off, int len)
{
    if (len <= 0 || off + len > d.size()) return false;
    for (int i = 0; i < len; ++i) {
        const auto b = static_cast<uint8_t>(d.at(off + i));
        if (b < 0x20 || b == 0x7F) return false;
    }
    return true;
}

// Length-prefixed strings in [from, to): first is the label, last the unit.
QStringList v5Strings(const QByteArray &d, qsizetype from, qsizetype to)
{
    QStringList out;
    qsizetype i = from;
    while (i + 4 <= to) {
        const uint32_t L = OlsKennfeldParser::peekU32(d, i);
        if (L >= 1 && L <= 120 && i + 4 + qsizetype(L) <= to
            && v5Printable(d, i + 4, int(L))) {
            out.append(decodeOlsString(d.constData() + i + 4, int(L)));
            i += 4 + L;
        } else {
            ++i;
        }
    }
    return out;
}

bool v5FiniteScale(double v)
{
    return std::isfinite(v) && std::fabs(v) < 1e12;
}

} // namespace

QVector<MapInfo> OlsKennfeldParser::parseAllWinOls5(const QByteArray &data,
                                                    qsizetype regionEnd,
                                                    uint32_t romSize,
                                                    QStringList *warnings)
{
    QVector<MapInfo> maps;
    QSet<QString> seenKeys;
    QHash<QString, int> nameCount;
    const uint32_t addrLimit = romSize ? romSize : 0x10000000u;
    const qsizetype end = qMin(regionEnd, data.size());

    qsizetype off = 0x18;
    while (off + 4 + 0x130 < end) {
        const uint32_t L = peekU32(data, off);
        if (L < 1 || L > 200 || !v5Printable(data, off + 4, int(L))) { ++off; continue; }
        const qsizetype b = off + 4 + L;
        if (b + 0x130 > end) { ++off; continue; }

        const uint32_t dt  = peekU32(data, b + 0x14);
        const uint32_t bpc = peekU32(data, b + 0x18);
        const int dtBytes = v5BytesFromDataType(dt);
        const uint8_t sgn = static_cast<uint8_t>(data.at(b + 0x9A));
        const uint32_t nx = peekU32(data, b + 0x9D);
        const uint32_t ny = peekU32(data, b + 0xA1);
        if (dtBytes == 0 || (bpc != 1 && bpc != 2 && bpc != 4 && bpc != 8)
            || sgn > 1 || nx < 1 || nx > 256 || ny < 1 || ny > 256) {
            ++off; continue;
        }

        // Data block: f64 factor, f64 offset, u32 start, u32 end.
        const qsizetype cells = qsizetype(nx) * ny;
        qsizetype q = -1;
        for (qsizetype t = b + 0xA5; t + 8 <= qMin(end, b + 0x400); ++t) {
            const uint32_t st = peekU32(data, t), en = peekU32(data, t + 4);
            if (st == 0 || st >= addrLimit || en <= st || en > addrLimit) continue;
            const qsizetype span = qsizetype(en) - st;
            if (span != cells * dtBytes && span != cells * 2 && span != cells * 4)
                continue;
            if (!v5FiniteScale(peekF64(data, t - 16)) || !v5FiniteScale(peekF64(data, t - 8)))
                continue;
            q = t;
            break;
        }
        if (q < 0) { ++off; continue; }

        const uint32_t romStart = peekU32(data, q);
        const double factor = peekF64(data, q - 16);
        const double offsetV = peekF64(data, q - 8);
        const QStringList valStrs = v5Strings(data, b + 0xA5, q - 16);

        // Axis blocks.
        struct Ax { uint32_t addr, dt, bytes; bool sgn; double f, o; QStringList strs; };
        QVector<Ax> axes;
        qsizetype prev = q + 8, p = q + 8;
        const qsizetype axLimit = qMin(end - 48, q + 8 + 0x300);
        while (p < axLimit && axes.size() < 2) {
            const uint32_t a = peekU32(data, p + 4), adt = peekU32(data, p + 8),
                           ab = peekU32(data, p + 12);
            if (peekU32(data, p) == 1 && a > 0 && a < addrLimit
                && v5BytesFromDataType(adt) != 0 && (ab == 1 || ab == 2 || ab == 4 || ab == 8)
                && peekU32(data, p + 16) == 0x0A) {
                Ax ax;
                ax.addr = a; ax.dt = adt; ax.bytes = ab;
                ax.sgn = static_cast<uint8_t>(data.at(p + 42)) != 0;
                ax.f = peekF64(data, p - 16); ax.o = peekF64(data, p - 8);
                if (!v5FiniteScale(ax.f) || ax.f == 0.0) ax.f = 1.0;
                if (!v5FiniteScale(ax.o)) ax.o = 0.0;
                ax.strs = v5Strings(data, prev, p - 16);
                axes.append(ax);
                prev = p + 20;
                p += 20;
            } else {
                ++p;
            }
        }
        const qsizetype recordNext = axes.isEmpty() ? q + 8 : prev;

        QString name = decodeOlsString(data.constData() + off + 4, int(L));
        const QString key = QStringLiteral("%1/%2/%3").arg(romStart).arg(nx).arg(ny);
        if (seenKeys.contains(key)) {    // second (duplicate) map list
            off = recordNext;
            continue;
        }
        seenKeys.insert(key);

        MapInfo mi;
        const int dup = nameCount.value(name, 0);
        nameCount[name] = dup + 1;
        mi.id = name;
        mi.name = name;
        if (name.startsWith(QStringLiteral("Kennfeld \"")) || dup > 0) {
            // WinOLS placeholder names repeat hundreds of times; make them
            // unique and sortable by appending the ROM address.
            const QString hex = QString::number(romStart, 16).toUpper()
                                    .rightJustified(6, QLatin1Char('0'));
            mi.name = name + QStringLiteral(" @") + hex;
        }
        mi.markerPos = int(off);
        mi.rawAddress = romStart;
        mi.address = romStart;
        mi.dimensions = { int(nx), int(ny) };
        mi.cellDataType = dt;
        mi.cellBigEndian = v5IsBigEndian(dt);
        mi.dataSize = dtBytes;
        mi.dataSigned = (sgn != 0);
        mi.length = int(cells * dtBytes);
        mi.columnMajor = false;
        mi.linkConfidence = 100;
        mi.type = (nx <= 1 && ny <= 1) ? QStringLiteral("VALUE")
                : (ny <= 1 ? QStringLiteral("CURVE") : QStringLiteral("MAP"));
        const double fac = (factor == 0.0) ? 1.0 : factor;
        if (fac != 1.0 || offsetV != 0.0) {
            mi.hasScaling = true;
            mi.scaling.type = CompuMethod::Type::Linear;
            mi.scaling.linA = fac;
            mi.scaling.linB = offsetV;
        }
        if (valStrs.size() >= 2) mi.scaling.unit = valStrs.last();
        if (!valStrs.isEmpty()) mi.description = valStrs.first();

        auto fillAxis = [](AxisInfo &out, const Ax &ax, int count) {
            out.hasPtsAddress = true;
            out.ptsAddress = ax.addr;
            out.ptsCount = count;
            out.ptsDataType = ax.dt;
            out.ptsBigEndian = v5IsBigEndian(ax.dt);
            out.ptsSigned = ax.sgn;
            out.ptsDataSize = v5BytesFromDataType(ax.dt);
            if (!ax.strs.isEmpty()) out.inputName = ax.strs.first();
            out.hasScaling = (ax.f != 1.0 || ax.o != 0.0);
            out.scaling.type = CompuMethod::Type::Linear;
            out.scaling.linA = ax.f;
            out.scaling.linB = ax.o;
            if (ax.strs.size() >= 2) out.scaling.unit = ax.strs.last();
        };
        if (axes.size() >= 1 && nx > 1) fillAxis(mi.xAxis, axes[0], int(nx));
        if (axes.size() >= 2 && ny > 1) fillAxis(mi.yAxis, axes[1], int(ny));

        maps.append(mi);
        off = recordNext;
    }

    if (warnings && !maps.isEmpty())
        warnings->append(OlsKennfeldParser::tr("WinOLS 5 layout: %1 maps parsed")
                             .arg(maps.size()));
    return maps;
}

}
