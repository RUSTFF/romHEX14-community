/*
 * This file is part of romHEX14.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QHash>
#include <QString>
#include <QVector>
#include "../../romdata.h"

// WinOLS 5 map objects (KpMapObject) and folder records.
//
// WinOLS 5 serialises maps with the same routine in .ols projects and in .kp
// map packs.  The grammar is the schema-750 grammar documented in
// KpImporter.cpp, extended by three int32 fields that exist in schema 859 but
// not in 839:
//   * after the gate-93 byte, before the display name
//   * after the properties block (+0x34)
//   * in each axis descriptor, after +0x98, before the int/string vectors
// Verified against WinOLS-written files of schema 839 (.ols, 650 maps) and
// 859 (.ols and .kp, 259 maps); every record is consumed byte-exactly.
//
// Container framing around the records:
//   map list     u8 0, u32 count, count x KpMapObject
//   folder table 839: marker[8], u32 count, records
//                859: marker[8], u32 0, marker[8], u32 count, records
// The 8-byte markers are per-file values; readers skip them and writers copy
// them from a template.
namespace ols {

struct Wo5Axis {
    QString  name;            // axis description
    QString  unit;
    QString  id;              // technical id
    double   factor = 1.0;
    double   offset = 0.0;
    bool     fromRom = false; // +0x64 == 1: breakpoints are read from ROM
    uint32_t address = 0;
    uint32_t dataType = 1;    // OLS type enum (1 u8, 2/3 u16 BE/LE, 4/5 u32, 6/7 float)
    int32_t  elementSize = 1;
    bool     isSigned = false;
    int32_t  decimals = -1;
};

struct Wo5MapObject {
    QString  description;     // +0x208 structured string
    QString  name;            // display name
    QString  id;              // technical id
    QString  unit;
    uint32_t kind = 2;        // 1 hexdump, 2 value, 3 curve, 4 map
    uint32_t dataType = 1;    // OLS type enum, see Wo5Axis::dataType
    int32_t  elementSize = 1;
    uint32_t folderId = 0;
    int32_t  columns = 1;
    int32_t  rows = 1;
    int32_t  decimals = -1;
    bool     isSigned = false;
    double   factor = 1.0;
    double   offset = 0.0;
    uint32_t start = 0;       // first data byte (image offset)
    uint32_t end = 0;         // one past the last data byte
    uint32_t imageSize = 0;   // +0x4c / +0x34: size of the binary
    Wo5Axis  x, y;
};

struct Wo5Folder {
    uint32_t id = 0;
    uint32_t parentId = 0;
    QString  name;
    int32_t  value302a = -1;
};

namespace wo5 {

// Schemas whose map-object grammar is known.  Versions between 839 and 859
// are read with the 859 gates (the exact gate version is not known).
bool isKnownSchema(uint32_t version);

bool readMapObject(const QByteArray &data, qsizetype &pos, uint32_t version,
                   Wo5MapObject &out, QString *error = nullptr);

// pos points at the leading u8 of the list.  On success pos is advanced past
// the last record.
bool readMapList(const QByteArray &data, qsizetype &pos, uint32_t version,
                 QVector<Wo5MapObject> &out, QString *error = nullptr);

// pos points at the first marker.  On success pos is advanced past the table.
bool readFolderTable(const QByteArray &data, qsizetype &pos, uint32_t version,
                     QVector<Wo5Folder> &out, QByteArray *marker1 = nullptr,
                     QByteArray *marker2 = nullptr, QString *error = nullptr);

// Finds the map list inside a WinOLS 5 .ols file (searching [from, to)).
// A position is accepted only if the whole list and the folder table behind
// it parse.  Returns -1 if none is found.
qsizetype locateOlsMapList(const QByteArray &file, uint32_t version,
                           qsizetype from, qsizetype to);

QHash<uint32_t, QString> folderPaths(const QVector<Wo5Folder> &folders);

// kind 1 (hexdump) and unknown kinds yield false.
bool toMapInfo(const Wo5MapObject &obj, const QHash<uint32_t, QString> &paths,
               MapInfo &out);

// Schema-859 serialisation.
void writeMapObject(QByteArray &out, const Wo5MapObject &obj);
void writeFolder(QByteArray &out, const Wo5Folder &folder);

int elementSizeForType(uint32_t dataType);  // 0 for unknown types
bool isBigEndianType(uint32_t dataType);

} // namespace wo5
} // namespace ols
