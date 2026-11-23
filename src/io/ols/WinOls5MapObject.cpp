/*
 * This file is part of romHEX14.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "WinOls5MapObject.h"

#include <QtEndian>
#include <cmath>
#include <cstring>

namespace ols {
namespace wo5 {

namespace {

constexpr int32_t kMaxString = 1 << 20;
constexpr int32_t kMaxEntries = 4096;
constexpr int32_t kMaxVector = 1 << 22;

// Windows-1252 code points for 0x80..0x9F (0 = undefined).
const char16_t kCp1252High[32] = {
    0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0, 0x017D, 0,
    0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178,
};

QString decodeCp1252(const char *p, int n)
{
    QString s;
    s.reserve(n);
    for (int i = 0; i < n; ++i) {
        const auto b = static_cast<uint8_t>(p[i]);
        if (b >= 0x80 && b < 0xA0 && kCp1252High[b - 0x80])
            s.append(QChar(kCp1252High[b - 0x80]));
        else
            s.append(QChar(b));
    }
    return s;
}

QByteArray encodeCp1252(const QString &s)
{
    QByteArray out;
    out.reserve(s.size());
    for (QChar c : s) {
        const char16_t u = c.unicode();
        if (u < 0x80 || (u >= 0xA0 && u <= 0xFF)) {
            out.append(static_cast<char>(u));
            continue;
        }
        char mapped = '?';
        for (int i = 0; i < 32; ++i)
            if (kCp1252High[i] == u) { mapped = static_cast<char>(0x80 + i); break; }
        out.append(mapped);
    }
    return out;
}

class Reader {
public:
    Reader(const QByteArray &d, qsizetype p) : m_d(d), m_p(p) {}

    bool ok() const { return m_ok; }
    qsizetype pos() const { return m_p; }
    const QString &error() const { return m_err; }

    void fail(const QString &what)
    {
        if (m_ok) m_err = QStringLiteral("%1 at 0x%2").arg(what).arg(m_p, 0, 16);
        m_ok = false;
    }

    bool need(qsizetype n)
    {
        if (!m_ok) return false;
        if (n < 0 || m_p < 0 || m_p + n > m_d.size()) { fail(QStringLiteral("truncated")); return false; }
        return true;
    }

    uint8_t u8()
    {
        if (!need(1)) return 0;
        return static_cast<uint8_t>(m_d.at(m_p++));
    }
    uint32_t u32()
    {
        if (!need(4)) return 0;
        const uint32_t v = qFromLittleEndian<uint32_t>(
            reinterpret_cast<const uchar *>(m_d.constData() + m_p));
        m_p += 4;
        return v;
    }
    int32_t i32() { return static_cast<int32_t>(u32()); }
    double f64()
    {
        if (!need(8)) return 0.0;
        const uint64_t bits = qFromLittleEndian<uint64_t>(
            reinterpret_cast<const uchar *>(m_d.constData() + m_p));
        m_p += 8;
        double v;
        std::memcpy(&v, &bits, sizeof v);
        return v;
    }
    void skip(qsizetype n) { if (need(n)) m_p += n; }

    // u32 length marker; negative markers are references / absent values.
    QString string()
    {
        const int32_t n = i32();
        if (!m_ok || n <= 0) return QString();
        if (n > kMaxString) { fail(QStringLiteral("implausible string length")); return QString(); }
        if (!need(n)) return QString();
        const QString s = decodeCp1252(m_d.constData() + m_p, n);
        m_p += n;
        return s;
    }

    QString structuredString()
    {
        const QString s = string();
        skip(8);
        const int32_t count = i32();
        if (!m_ok) return s;
        if (count < 0 || count > kMaxEntries) { fail(QStringLiteral("implausible entry count")); return s; }
        for (int32_t i = 0; i < count && m_ok; ++i) { string(); i32(); }
        return s;
    }

    void intVector()
    {
        const int32_t n = i32();
        if (!m_ok || n <= 0) return;           // -1 marks an absent vector
        if (n > kMaxVector) { fail(QStringLiteral("implausible vector")); return; }
        skip(qsizetype(n) * 4);
    }
    void stringVector()
    {
        const int32_t n = i32();
        if (!m_ok || n <= 0) return;
        if (n > kMaxEntries) { fail(QStringLiteral("implausible string vector")); return; }
        for (int32_t i = 0; i < n && m_ok; ++i) string();
    }
    void byteVector()
    {
        const int32_t n = i32();
        if (!m_ok || n <= 0) return;
        if (n > kMaxVector) { fail(QStringLiteral("implausible byte vector")); return; }
        skip(n);
    }

private:
    const QByteArray &m_d;
    qsizetype m_p;
    bool m_ok = true;
    QString m_err;
};

bool hasNew859Fields(uint32_t version) { return version > 839; }

void readAxis(Reader &r, uint32_t version, Wo5Axis &a)
{
    a.name = r.structuredString();
    a.unit = r.string();
    a.factor = r.f64();
    a.offset = r.f64();
    a.fromRom = (r.u32() == 1);
    a.address = r.u32();
    a.dataType = r.u32();
    a.elementSize = r.i32();
    r.i32();                         // record type
    r.u8(); r.u8();                  // +0x80, +0x81
    r.skip(8);                       // +0x58
    r.i32();                         // precision
    r.i32();                         // +0x8c
    a.decimals = r.i32();            // +0x90
    a.isSigned = r.u8() != 0;
    r.byteVector();                  // +0x168
    r.i32();                         // +0x6c
    r.u32();                         // +0x60
    a.id = r.string();
    const int32_t n190 = r.i32();
    if (n190 < 0 || n190 > kMaxEntries) { r.fail(QStringLiteral("implausible axis list")); return; }
    for (int32_t i = 0; i < n190 && r.ok(); ++i) r.structuredString();
    r.u32(); r.i32(); r.i32();       // +0x88, +0x94, +0x98
    if (hasNew859Fields(version)) r.i32();
    r.intVector();                   // +0xa0
    r.stringVector();                // +0xc8
}

// ── writer ──────────────────────────────────────────────────────────────────

void putU8(QByteArray &o, uint8_t v) { o.append(static_cast<char>(v)); }
void putU32(QByteArray &o, uint32_t v)
{
    char b[4];
    qToLittleEndian(v, b);
    o.append(b, 4);
}
void putI32(QByteArray &o, int32_t v) { putU32(o, static_cast<uint32_t>(v)); }
void putF64(QByteArray &o, double v)
{
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof bits);
    char b[8];
    qToLittleEndian(bits, b);
    o.append(b, 8);
}
void putZeros(QByteArray &o, int n) { o.append(QByteArray(n, '\0')); }
void putHex(QByteArray &o, const char *hex) { o.append(QByteArray::fromHex(hex)); }

void putString(QByteArray &o, const QString &s, int32_t emptyMarker)
{
    if (s.isEmpty()) { putI32(o, emptyMarker); return; }
    const QByteArray b = encodeCp1252(s);
    putI32(o, int32_t(b.size()));
    o.append(b);
}
void putStructured(QByteArray &o, const QString &s, int32_t emptyMarker)
{
    putString(o, s, emptyMarker);
    putZeros(o, 8);
    putI32(o, 0);
}

void writeAxis(QByteArray &o, const Wo5Axis &a, bool used)
{
    if (!used) {
        // WinOLS' own serialisation of an axis without data
        putStructured(o, QString(), -1);
        putI32(o, -1);                  // unit
        putF64(o, 1.0); putF64(o, 0.0);
        putU32(o, 0); putU32(o, 0);     // from ROM, address
        putU32(o, 1); putI32(o, 1);     // data type, element size
        putI32(o, 16);                  // record type
        putU8(o, 1); putU8(o, 0);
        putZeros(o, 8);
        putI32(o, 0); putI32(o, -1); putI32(o, -1);
        putU8(o, 0);
        putI32(o, 0);                   // byte vector
        putI32(o, 0); putU32(o, 0xFFFFFFFFu);
        putI32(o, 0);                   // id
        putI32(o, 0);                   // +0x190 list
        putU32(o, 0); putI32(o, 0); putI32(o, 0);
        putI32(o, -1);                  // 859 field
        putI32(o, 0); putI32(o, 0);     // vectors
        return;
    }
    putStructured(o, a.name, -1);
    putString(o, a.unit, -1);
    putF64(o, a.factor); putF64(o, a.offset);
    putU32(o, a.fromRom ? 1 : 0);
    putU32(o, a.fromRom ? a.address : 0);
    putU32(o, a.dataType); putI32(o, a.elementSize);
    putI32(o, 10);
    putU8(o, 0); putU8(o, 0);
    putZeros(o, 8);
    putI32(o, 0); putI32(o, -1); putI32(o, a.decimals);
    putU8(o, a.isSigned ? 1 : 0);
    putI32(o, 0);
    putI32(o, 0); putU32(o, 0xFFFFFFFFu);
    putString(o, a.id, 0);
    putI32(o, 0);
    putU32(o, 0); putI32(o, 0); putI32(o, 0);
    putI32(o, -1);
    putI32(o, 0); putI32(o, 0);
}

} // namespace

bool isKnownSchema(uint32_t version) { return version >= 839 && version <= 859; }

int elementSizeForType(uint32_t t)
{
    switch (t) {
    case 1: case 8: case 9:             return 1;
    case 2: case 3:                     return 2;
    case 4: case 5: case 6: case 7:     return 4;
    case 10: case 11: case 12: case 13: return 8;
    default:                            return 0;
    }
}

bool isBigEndianType(uint32_t t) { return t == 2 || t == 4 || t == 6 || t == 10 || t == 12; }

bool readMapObject(const QByteArray &data, qsizetype &pos, uint32_t version,
                   Wo5MapObject &o, QString *error)
{
    Reader r(data, pos);
    r.u8();                          // +0x1a0
    r.i32();                         // +0x90
    o.description = r.structuredString();
    r.u8();                          // gate-93 byte
    if (hasNew859Fields(version)) r.i32();
    o.name = r.structuredString();
    o.kind = r.u32();
    r.u32();                         // constant 2
    o.dataType = r.u32();
    o.elementSize = r.i32();
    r.i32();                         // record type
    o.folderId = r.u32();
    o.id = r.string();
    r.i32(); r.i32(); r.i32();       // +0x58, precision, +0x5c
    r.u8();                          // +0x50
    r.u32();                         // +0xc0
    r.skip(6 * 8);                   // value ranges
    r.skip(6 * 8);                   // float parameters
    r.u8();
    o.isSigned = r.u8() != 0;        // +0x105
    r.u8(); r.u8();
    o.columns = r.i32();
    o.rows = r.i32();
    r.skip(8);
    o.decimals = r.i32();            // +0x198
    r.string();                      // properties name
    o.unit = r.string();
    o.factor = r.f64();
    o.offset = r.f64();
    o.start = r.u32();
    o.end = r.u32();
    o.imageSize = r.u32();
    r.skip(8);
    r.i32(); r.i32(); r.i32(); r.i32();
    r.u32();                         // +0x34
    if (hasNew859Fields(version)) r.i32();
    readAxis(r, version, o.x);
    if (r.ok()) readAxis(r, version, o.y);
    r.skip(14 + 22 + 44 + 4 + 20 + 4 + 8 + 4 + 4);   // tail scalars
    r.intVector();                   // +0x1b8
    r.stringVector();                // +0x1e0
    r.skip(4 + 12 + 4);
    if (!r.ok()) {
        if (error) *error = r.error();
        return false;
    }
    if (o.columns < 0 || o.rows < 0 || o.columns > 1 << 20 || o.rows > 1 << 20) {
        if (error) *error = QStringLiteral("implausible dimensions");
        return false;
    }
    pos = r.pos();
    return true;
}

bool readMapList(const QByteArray &data, qsizetype &pos, uint32_t version,
                 QVector<Wo5MapObject> &out, QString *error)
{
    Reader r(data, pos);
    if (r.u8() != 0) { if (error) *error = QStringLiteral("map list flag"); return false; }
    const uint32_t count = r.u32();
    if (!r.ok() || count > 1000000) { if (error) *error = QStringLiteral("map list count"); return false; }
    qsizetype p = r.pos();
    QVector<Wo5MapObject> maps;
    maps.reserve(int(qMin<uint32_t>(count, 100000)));
    for (uint32_t i = 0; i < count; ++i) {
        Wo5MapObject m;
        QString err;
        if (!readMapObject(data, p, version, m, &err)) {
            if (error) *error = QStringLiteral("map %1: %2").arg(i).arg(err);
            return false;
        }
        maps.append(m);
    }
    out = maps;
    pos = p;
    return true;
}

bool readFolderTable(const QByteArray &data, qsizetype &pos, uint32_t version,
                     QVector<Wo5Folder> &out, QByteArray *marker1, QByteArray *marker2,
                     QString *error)
{
    Reader r(data, pos);
    const qsizetype m1 = r.pos();
    r.skip(8);
    qsizetype m2 = -1;
    if (hasNew859Fields(version)) {
        if (r.u32() != 0) { if (error) *error = QStringLiteral("folder table reserved field"); return false; }
        m2 = r.pos();
        r.skip(8);
    }
    const uint32_t count = r.u32();
    if (!r.ok() || count > 100000) { if (error) *error = QStringLiteral("folder count"); return false; }
    QVector<Wo5Folder> folders;
    for (uint32_t i = 0; i < count && r.ok(); ++i) {
        Wo5Folder f;
        f.id = r.u32();
        f.parentId = r.u32();
        f.name = r.string();
        r.i32(); r.i32();
        const int32_t entries = r.i32();
        if (entries < 0 || entries > kMaxEntries) { r.fail(QStringLiteral("folder entries")); break; }
        for (int32_t k = 0; k < entries && r.ok(); ++k) { r.string(); r.i32(); }
        r.u8();
        r.byteVector();
        r.u8(); r.u32(); r.u32(); r.u8();
        r.string();
        r.u8(); r.u8(); r.u8();
        f.value302a = r.i32();
        r.i32(); r.i32();
        folders.append(f);
    }
    if (!r.ok()) { if (error) *error = r.error(); return false; }
    if (marker1) *marker1 = data.mid(m1, 8);
    if (marker2) *marker2 = (m2 >= 0) ? data.mid(m2, 8) : QByteArray();
    out = folders;
    pos = r.pos();
    return true;
}

qsizetype locateOlsMapList(const QByteArray &file, uint32_t version,
                           qsizetype from, qsizetype to)
{
    to = qMin(to, file.size() - 10);
    const auto *d = reinterpret_cast<const uchar *>(file.constData());
    for (qsizetype p = qMax<qsizetype>(from, 0); p < to; ++p) {
        // u8 0, u32 count, then the first record's u8 +0x1a0 and i32 +0x90.
        if (d[p] != 0) continue;
        const uint32_t count = qFromLittleEndian<uint32_t>(d + p + 1);
        if (count == 0 || count > 1000000) continue;
        if (d[p + 5] > 1) continue;
        qsizetype q = p;
        QVector<Wo5MapObject> maps;
        if (!readMapList(file, q, version, maps)) continue;
        QVector<Wo5Folder> folders;
        qsizetype f = q;
        if (!readFolderTable(file, f, version, folders)) continue;
        return p;
    }
    return -1;
}

QHash<uint32_t, QString> folderPaths(const QVector<Wo5Folder> &folders)
{
    QHash<uint32_t, const Wo5Folder *> byId;
    for (const auto &f : folders) byId.insert(f.id, &f);
    QHash<uint32_t, QString> out;
    for (const auto &f : folders) {
        // Built-in roots (Meine Kennfelder, Hexdump, Potentielle Kennfelder,
        // Tabellen) are not part of the user-visible path.
        if (f.id <= 3) continue;
        QStringList parts{ f.name };
        uint32_t parent = f.parentId;
        int guard = 0;
        while (parent > 3 && byId.contains(parent) && ++guard < 64) {
            parts.prepend(byId.value(parent)->name);
            parent = byId.value(parent)->parentId;
        }
        out.insert(f.id, parts.join(QLatin1Char('/')));
    }
    return out;
}

bool toMapInfo(const Wo5MapObject &o, const QHash<uint32_t, QString> &paths, MapInfo &m)
{
    if (o.kind < 2 || o.kind > 5) return false;   // 1 = hexdump view
    const int esz = elementSizeForType(o.dataType) ? elementSizeForType(o.dataType)
                                                   : qBound(1, o.elementSize, 8);
    m = MapInfo();
    m.name = o.name.isEmpty() ? (o.id.isEmpty() ? QStringLiteral("Map") : o.id) : o.name;
    m.id = o.id;
    if (!o.description.isEmpty() && o.description != m.name)
        m.description = o.description;
    m.folderPath = paths.value(o.folderId);
    m.rawAddress = o.start;
    m.address = o.start;
    m.cellDataType = o.dataType;
    m.cellBigEndian = isBigEndianType(o.dataType);
    m.dataSize = esz;
    m.dataSigned = o.isSigned;
    m.columnMajor = false;
    m.linkConfidence = 100;
    if (o.kind == 2) { m.dimensions = { 1, 1 }; m.type = QStringLiteral("VALUE"); }
    else if (o.kind == 3) { m.dimensions = { qMax(1, o.columns), 1 }; m.type = QStringLiteral("CURVE"); }
    else { m.dimensions = { qMax(1, o.columns), qMax(1, o.rows) }; m.type = QStringLiteral("MAP"); }
    m.length = m.dimensions.x * m.dimensions.y * esz;

    auto scaling = [](double f, double off, const QString &unit, int decimals, CompuMethod &cm) {
        if (!std::isfinite(f) || f == 0.0) f = 1.0;
        if (!std::isfinite(off)) off = 0.0;
        cm.type = CompuMethod::Type::Linear;
        cm.linA = f;
        cm.linB = off;
        cm.unit = unit;
        if (decimals >= 0 && decimals <= 9)
            cm.format = QStringLiteral("%.%1f").arg(decimals);
        return f != 1.0 || off != 0.0 || !unit.isEmpty();
    };
    m.hasScaling = scaling(o.factor, o.offset, o.unit, o.decimals, m.scaling);

    auto axis = [&](const Wo5Axis &a, int count, AxisInfo &ai) {
        if (count <= 1) return;
        ai.inputName = a.name;
        ai.hasScaling = scaling(a.factor, a.offset, a.unit, a.decimals, ai.scaling);
        if (!a.fromRom || a.address == 0) return;
        ai.hasPtsAddress = true;
        ai.ptsAddress = a.address;
        ai.ptsCount = count;
        ai.ptsDataType = a.dataType;
        ai.ptsBigEndian = isBigEndianType(a.dataType);
        ai.ptsDataSize = elementSizeForType(a.dataType) ? elementSizeForType(a.dataType)
                                                        : qBound(1, a.elementSize, 8);
        ai.ptsSigned = a.isSigned;
    };
    axis(o.x, m.dimensions.x, m.xAxis);
    axis(o.y, m.dimensions.y, m.yAxis);
    return true;
}

void writeMapObject(QByteArray &out, const Wo5MapObject &o)
{
    const bool hasX = o.kind >= 3;
    const bool hasY = o.kind == 4;
    putU8(out, 0);
    putI32(out, -1);
    putStructured(out, o.description, 0);
    putU8(out, 0);
    putI32(out, 0);                          // 859 field
    putStructured(out, o.name, 0);
    putU32(out, o.kind);
    putU32(out, 2);
    putU32(out, o.dataType);
    putI32(out, o.elementSize);
    putI32(out, 10);
    putU32(out, o.folderId);
    putString(out, o.id, 0);
    putI32(out, 0); putI32(out, 16); putI32(out, 0);
    putU8(out, 0);
    putU32(out, 1);
    // value ranges as written by WinOLS
    putHex(out, "0000000000000000" "0000000000007040" "0000000000000000"
                "00000000e0ffef40" "0000000000000000" "0000e0ffffffef41");
    putZeros(out, 6 * 8);
    putU8(out, 0);
    putU8(out, o.isSigned ? 1 : 0);
    putU8(out, 0); putU8(out, 0);
    putI32(out, o.columns);
    putI32(out, o.rows);
    putZeros(out, 8);
    putI32(out, o.decimals);
    putI32(out, 0);                          // properties name
    putString(out, o.unit, -1);
    putF64(out, o.factor);
    putF64(out, o.offset);
    putU32(out, o.start);
    putU32(out, o.end);
    putU32(out, o.imageSize);
    putZeros(out, 8);
    putI32(out, 0); putI32(out, 0); putI32(out, 0); putI32(out, 0);
    putU32(out, o.imageSize);
    putI32(out, 0);                          // 859 field
    writeAxis(out, o.x, hasX);
    writeAxis(out, o.y, hasY);
    putZeros(out, 6);
    putI32(out, o.columns);
    putI32(out, o.rows);
    putHex(out, "010000000101000000000000f03f000000000000f03f");
    putHex(out, "ffffffff010000000000406a40000000000000f03f0000000000000000"
                "ffffffff0000000000000000010101");
    putHex(out, "ffffffff");
    putZeros(out, 20 + 4 + 8 + 4 + 4);
    putI32(out, 0); putI32(out, 0);          // vectors
    putHex(out, "ffffffff");
    putZeros(out, 12 + 4);
}

void writeFolder(QByteArray &out, const Wo5Folder &f)
{
    putU32(out, f.id);
    putU32(out, f.parentId);
    putString(out, f.name, 0);
    putI32(out, 0); putI32(out, 0); putI32(out, 0);
    putU8(out, 0);
    putI32(out, 4); putHex(out, "01010101");
    putU8(out, 0); putU32(out, 0); putU32(out, 0); putU8(out, 0);
    putI32(out, 0);
    putU8(out, 0); putU8(out, 0); putU8(out, 0);
    putI32(out, f.value302a); putI32(out, 0); putI32(out, 0);
}

} // namespace wo5
} // namespace ols
