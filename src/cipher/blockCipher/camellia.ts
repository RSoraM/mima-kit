import { createCipher } from '../../core/cipher'
import { KitError, U8, rotateL32, rotateR32 } from '../../core/utils'

// * Constants

const SBox1_1110 = new Uint32Array([0x70707000, 0x82828200, 0x2C2C2C00, 0xECECEC00, 0xB3B3B300, 0x27272700, 0xC0C0C000, 0xE5E5E500, 0xE4E4E400, 0x85858500, 0x57575700, 0x35353500, 0xEAEAEA00, 0x0C0C0C00, 0xAEAEAE00, 0x41414100, 0x23232300, 0xEFEFEF00, 0x6B6B6B00, 0x93939300, 0x45454500, 0x19191900, 0xA5A5A500, 0x21212100, 0xEDEDED00, 0x0E0E0E00, 0x4F4F4F00, 0x4E4E4E00, 0x1D1D1D00, 0x65656500, 0x92929200, 0xBDBDBD00, 0x86868600, 0xB8B8B800, 0xAFAFAF00, 0x8F8F8F00, 0x7C7C7C00, 0xEBEBEB00, 0x1F1F1F00, 0xCECECE00, 0x3E3E3E00, 0x30303000, 0xDCDCDC00, 0x5F5F5F00, 0x5E5E5E00, 0xC5C5C500, 0x0B0B0B00, 0x1A1A1A00, 0xA6A6A600, 0xE1E1E100, 0x39393900, 0xCACACA00, 0xD5D5D500, 0x47474700, 0x5D5D5D00, 0x3D3D3D00, 0xD9D9D900, 0x01010100, 0x5A5A5A00, 0xD6D6D600, 0x51515100, 0x56565600, 0x6C6C6C00, 0x4D4D4D00, 0x8B8B8B00, 0x0D0D0D00, 0x9A9A9A00, 0x66666600, 0xFBFBFB00, 0xCCCCCC00, 0xB0B0B000, 0x2D2D2D00, 0x74747400, 0x12121200, 0x2B2B2B00, 0x20202000, 0xF0F0F000, 0xB1B1B100, 0x84848400, 0x99999900, 0xDFDFDF00, 0x4C4C4C00, 0xCBCBCB00, 0xC2C2C200, 0x34343400, 0x7E7E7E00, 0x76767600, 0x05050500, 0x6D6D6D00, 0xB7B7B700, 0xA9A9A900, 0x31313100, 0xD1D1D100, 0x17171700, 0x04040400, 0xD7D7D700, 0x14141400, 0x58585800, 0x3A3A3A00, 0x61616100, 0xDEDEDE00, 0x1B1B1B00, 0x11111100, 0x1C1C1C00, 0x32323200, 0x0F0F0F00, 0x9C9C9C00, 0x16161600, 0x53535300, 0x18181800, 0xF2F2F200, 0x22222200, 0xFEFEFE00, 0x44444400, 0xCFCFCF00, 0xB2B2B200, 0xC3C3C300, 0xB5B5B500, 0x7A7A7A00, 0x91919100, 0x24242400, 0x08080800, 0xE8E8E800, 0xA8A8A800, 0x60606000, 0xFCFCFC00, 0x69696900, 0x50505000, 0xAAAAAA00, 0xD0D0D000, 0xA0A0A000, 0x7D7D7D00, 0xA1A1A100, 0x89898900, 0x62626200, 0x97979700, 0x54545400, 0x5B5B5B00, 0x1E1E1E00, 0x95959500, 0xE0E0E000, 0xFFFFFF00, 0x64646400, 0xD2D2D200, 0x10101000, 0xC4C4C400, 0x00000000, 0x48484800, 0xA3A3A300, 0xF7F7F700, 0x75757500, 0xDBDBDB00, 0x8A8A8A00, 0x03030300, 0xE6E6E600, 0xDADADA00, 0x09090900, 0x3F3F3F00, 0xDDDDDD00, 0x94949400, 0x87878700, 0x5C5C5C00, 0x83838300, 0x02020200, 0xCDCDCD00, 0x4A4A4A00, 0x90909000, 0x33333300, 0x73737300, 0x67676700, 0xF6F6F600, 0xF3F3F300, 0x9D9D9D00, 0x7F7F7F00, 0xBFBFBF00, 0xE2E2E200, 0x52525200, 0x9B9B9B00, 0xD8D8D800, 0x26262600, 0xC8C8C800, 0x37373700, 0xC6C6C600, 0x3B3B3B00, 0x81818100, 0x96969600, 0x6F6F6F00, 0x4B4B4B00, 0x13131300, 0xBEBEBE00, 0x63636300, 0x2E2E2E00, 0xE9E9E900, 0x79797900, 0xA7A7A700, 0x8C8C8C00, 0x9F9F9F00, 0x6E6E6E00, 0xBCBCBC00, 0x8E8E8E00, 0x29292900, 0xF5F5F500, 0xF9F9F900, 0xB6B6B600, 0x2F2F2F00, 0xFDFDFD00, 0xB4B4B400, 0x59595900, 0x78787800, 0x98989800, 0x06060600, 0x6A6A6A00, 0xE7E7E700, 0x46464600, 0x71717100, 0xBABABA00, 0xD4D4D400, 0x25252500, 0xABABAB00, 0x42424200, 0x88888800, 0xA2A2A200, 0x8D8D8D00, 0xFAFAFA00, 0x72727200, 0x07070700, 0xB9B9B900, 0x55555500, 0xF8F8F800, 0xEEEEEE00, 0xACACAC00, 0x0A0A0A00, 0x36363600, 0x49494900, 0x2A2A2A00, 0x68686800, 0x3C3C3C00, 0x38383800, 0xF1F1F100, 0xA4A4A400, 0x40404000, 0x28282800, 0xD3D3D300, 0x7B7B7B00, 0xBBBBBB00, 0xC9C9C900, 0x43434300, 0xC1C1C100, 0x15151500, 0xE3E3E300, 0xADADAD00, 0xF4F4F400, 0x77777700, 0xC7C7C700, 0x80808000, 0x9E9E9E00])
const SBox4_4404 = new Uint32Array([0x70700070, 0x2C2C002C, 0xB3B300B3, 0xC0C000C0, 0xE4E400E4, 0x57570057, 0xEAEA00EA, 0xAEAE00AE, 0x23230023, 0x6B6B006B, 0x45450045, 0xA5A500A5, 0xEDED00ED, 0x4F4F004F, 0x1D1D001D, 0x92920092, 0x86860086, 0xAFAF00AF, 0x7C7C007C, 0x1F1F001F, 0x3E3E003E, 0xDCDC00DC, 0x5E5E005E, 0x0B0B000B, 0xA6A600A6, 0x39390039, 0xD5D500D5, 0x5D5D005D, 0xD9D900D9, 0x5A5A005A, 0x51510051, 0x6C6C006C, 0x8B8B008B, 0x9A9A009A, 0xFBFB00FB, 0xB0B000B0, 0x74740074, 0x2B2B002B, 0xF0F000F0, 0x84840084, 0xDFDF00DF, 0xCBCB00CB, 0x34340034, 0x76760076, 0x6D6D006D, 0xA9A900A9, 0xD1D100D1, 0x04040004, 0x14140014, 0x3A3A003A, 0xDEDE00DE, 0x11110011, 0x32320032, 0x9C9C009C, 0x53530053, 0xF2F200F2, 0xFEFE00FE, 0xCFCF00CF, 0xC3C300C3, 0x7A7A007A, 0x24240024, 0xE8E800E8, 0x60600060, 0x69690069, 0xAAAA00AA, 0xA0A000A0, 0xA1A100A1, 0x62620062, 0x54540054, 0x1E1E001E, 0xE0E000E0, 0x64640064, 0x10100010, 0x00000000, 0xA3A300A3, 0x75750075, 0x8A8A008A, 0xE6E600E6, 0x09090009, 0xDDDD00DD, 0x87870087, 0x83830083, 0xCDCD00CD, 0x90900090, 0x73730073, 0xF6F600F6, 0x9D9D009D, 0xBFBF00BF, 0x52520052, 0xD8D800D8, 0xC8C800C8, 0xC6C600C6, 0x81810081, 0x6F6F006F, 0x13130013, 0x63630063, 0xE9E900E9, 0xA7A700A7, 0x9F9F009F, 0xBCBC00BC, 0x29290029, 0xF9F900F9, 0x2F2F002F, 0xB4B400B4, 0x78780078, 0x06060006, 0xE7E700E7, 0x71710071, 0xD4D400D4, 0xABAB00AB, 0x88880088, 0x8D8D008D, 0x72720072, 0xB9B900B9, 0xF8F800F8, 0xACAC00AC, 0x36360036, 0x2A2A002A, 0x3C3C003C, 0xF1F100F1, 0x40400040, 0xD3D300D3, 0xBBBB00BB, 0x43430043, 0x15150015, 0xADAD00AD, 0x77770077, 0x80800080, 0x82820082, 0xECEC00EC, 0x27270027, 0xE5E500E5, 0x85850085, 0x35350035, 0x0C0C000C, 0x41410041, 0xEFEF00EF, 0x93930093, 0x19190019, 0x21210021, 0x0E0E000E, 0x4E4E004E, 0x65650065, 0xBDBD00BD, 0xB8B800B8, 0x8F8F008F, 0xEBEB00EB, 0xCECE00CE, 0x30300030, 0x5F5F005F, 0xC5C500C5, 0x1A1A001A, 0xE1E100E1, 0xCACA00CA, 0x47470047, 0x3D3D003D, 0x01010001, 0xD6D600D6, 0x56560056, 0x4D4D004D, 0x0D0D000D, 0x66660066, 0xCCCC00CC, 0x2D2D002D, 0x12120012, 0x20200020, 0xB1B100B1, 0x99990099, 0x4C4C004C, 0xC2C200C2, 0x7E7E007E, 0x05050005, 0xB7B700B7, 0x31310031, 0x17170017, 0xD7D700D7, 0x58580058, 0x61610061, 0x1B1B001B, 0x1C1C001C, 0x0F0F000F, 0x16160016, 0x18180018, 0x22220022, 0x44440044, 0xB2B200B2, 0xB5B500B5, 0x91910091, 0x08080008, 0xA8A800A8, 0xFCFC00FC, 0x50500050, 0xD0D000D0, 0x7D7D007D, 0x89890089, 0x97970097, 0x5B5B005B, 0x95950095, 0xFFFF00FF, 0xD2D200D2, 0xC4C400C4, 0x48480048, 0xF7F700F7, 0xDBDB00DB, 0x03030003, 0xDADA00DA, 0x3F3F003F, 0x94940094, 0x5C5C005C, 0x02020002, 0x4A4A004A, 0x33330033, 0x67670067, 0xF3F300F3, 0x7F7F007F, 0xE2E200E2, 0x9B9B009B, 0x26260026, 0x37370037, 0x3B3B003B, 0x96960096, 0x4B4B004B, 0xBEBE00BE, 0x2E2E002E, 0x79790079, 0x8C8C008C, 0x6E6E006E, 0x8E8E008E, 0xF5F500F5, 0xB6B600B6, 0xFDFD00FD, 0x59590059, 0x98980098, 0x6A6A006A, 0x46460046, 0xBABA00BA, 0x25250025, 0x42420042, 0xA2A200A2, 0xFAFA00FA, 0x07070007, 0x55550055, 0xEEEE00EE, 0x0A0A000A, 0x49490049, 0x68680068, 0x38380038, 0xA4A400A4, 0x28280028, 0x7B7B007B, 0xC9C900C9, 0xC1C100C1, 0xE3E300E3, 0xF4F400F4, 0xC7C700C7, 0x9E9E009E])
const SBox2_0222 = new Uint32Array([0x00E0E0E0, 0x00050505, 0x00585858, 0x00D9D9D9, 0x00676767, 0x004E4E4E, 0x00818181, 0x00CBCBCB, 0x00C9C9C9, 0x000B0B0B, 0x00AEAEAE, 0x006A6A6A, 0x00D5D5D5, 0x00181818, 0x005D5D5D, 0x00828282, 0x00464646, 0x00DFDFDF, 0x00D6D6D6, 0x00272727, 0x008A8A8A, 0x00323232, 0x004B4B4B, 0x00424242, 0x00DBDBDB, 0x001C1C1C, 0x009E9E9E, 0x009C9C9C, 0x003A3A3A, 0x00CACACA, 0x00252525, 0x007B7B7B, 0x000D0D0D, 0x00717171, 0x005F5F5F, 0x001F1F1F, 0x00F8F8F8, 0x00D7D7D7, 0x003E3E3E, 0x009D9D9D, 0x007C7C7C, 0x00606060, 0x00B9B9B9, 0x00BEBEBE, 0x00BCBCBC, 0x008B8B8B, 0x00161616, 0x00343434, 0x004D4D4D, 0x00C3C3C3, 0x00727272, 0x00959595, 0x00ABABAB, 0x008E8E8E, 0x00BABABA, 0x007A7A7A, 0x00B3B3B3, 0x00020202, 0x00B4B4B4, 0x00ADADAD, 0x00A2A2A2, 0x00ACACAC, 0x00D8D8D8, 0x009A9A9A, 0x00171717, 0x001A1A1A, 0x00353535, 0x00CCCCCC, 0x00F7F7F7, 0x00999999, 0x00616161, 0x005A5A5A, 0x00E8E8E8, 0x00242424, 0x00565656, 0x00404040, 0x00E1E1E1, 0x00636363, 0x00090909, 0x00333333, 0x00BFBFBF, 0x00989898, 0x00979797, 0x00858585, 0x00686868, 0x00FCFCFC, 0x00ECECEC, 0x000A0A0A, 0x00DADADA, 0x006F6F6F, 0x00535353, 0x00626262, 0x00A3A3A3, 0x002E2E2E, 0x00080808, 0x00AFAFAF, 0x00282828, 0x00B0B0B0, 0x00747474, 0x00C2C2C2, 0x00BDBDBD, 0x00363636, 0x00222222, 0x00383838, 0x00646464, 0x001E1E1E, 0x00393939, 0x002C2C2C, 0x00A6A6A6, 0x00303030, 0x00E5E5E5, 0x00444444, 0x00FDFDFD, 0x00888888, 0x009F9F9F, 0x00656565, 0x00878787, 0x006B6B6B, 0x00F4F4F4, 0x00232323, 0x00484848, 0x00101010, 0x00D1D1D1, 0x00515151, 0x00C0C0C0, 0x00F9F9F9, 0x00D2D2D2, 0x00A0A0A0, 0x00555555, 0x00A1A1A1, 0x00414141, 0x00FAFAFA, 0x00434343, 0x00131313, 0x00C4C4C4, 0x002F2F2F, 0x00A8A8A8, 0x00B6B6B6, 0x003C3C3C, 0x002B2B2B, 0x00C1C1C1, 0x00FFFFFF, 0x00C8C8C8, 0x00A5A5A5, 0x00202020, 0x00898989, 0x00000000, 0x00909090, 0x00474747, 0x00EFEFEF, 0x00EAEAEA, 0x00B7B7B7, 0x00151515, 0x00060606, 0x00CDCDCD, 0x00B5B5B5, 0x00121212, 0x007E7E7E, 0x00BBBBBB, 0x00292929, 0x000F0F0F, 0x00B8B8B8, 0x00070707, 0x00040404, 0x009B9B9B, 0x00949494, 0x00212121, 0x00666666, 0x00E6E6E6, 0x00CECECE, 0x00EDEDED, 0x00E7E7E7, 0x003B3B3B, 0x00FEFEFE, 0x007F7F7F, 0x00C5C5C5, 0x00A4A4A4, 0x00373737, 0x00B1B1B1, 0x004C4C4C, 0x00919191, 0x006E6E6E, 0x008D8D8D, 0x00767676, 0x00030303, 0x002D2D2D, 0x00DEDEDE, 0x00969696, 0x00262626, 0x007D7D7D, 0x00C6C6C6, 0x005C5C5C, 0x00D3D3D3, 0x00F2F2F2, 0x004F4F4F, 0x00191919, 0x003F3F3F, 0x00DCDCDC, 0x00797979, 0x001D1D1D, 0x00525252, 0x00EBEBEB, 0x00F3F3F3, 0x006D6D6D, 0x005E5E5E, 0x00FBFBFB, 0x00696969, 0x00B2B2B2, 0x00F0F0F0, 0x00313131, 0x000C0C0C, 0x00D4D4D4, 0x00CFCFCF, 0x008C8C8C, 0x00E2E2E2, 0x00757575, 0x00A9A9A9, 0x004A4A4A, 0x00575757, 0x00848484, 0x00111111, 0x00454545, 0x001B1B1B, 0x00F5F5F5, 0x00E4E4E4, 0x000E0E0E, 0x00737373, 0x00AAAAAA, 0x00F1F1F1, 0x00DDDDDD, 0x00595959, 0x00141414, 0x006C6C6C, 0x00929292, 0x00545454, 0x00D0D0D0, 0x00787878, 0x00707070, 0x00E3E3E3, 0x00494949, 0x00808080, 0x00505050, 0x00A7A7A7, 0x00F6F6F6, 0x00777777, 0x00939393, 0x00868686, 0x00838383, 0x002A2A2A, 0x00C7C7C7, 0x005B5B5B, 0x00E9E9E9, 0x00EEEEEE, 0x008F8F8F, 0x00010101, 0x003D3D3D])
const SBox3_3033 = new Uint32Array([0x38003838, 0x41004141, 0x16001616, 0x76007676, 0xD900D9D9, 0x93009393, 0x60006060, 0xF200F2F2, 0x72007272, 0xC200C2C2, 0xAB00ABAB, 0x9A009A9A, 0x75007575, 0x06000606, 0x57005757, 0xA000A0A0, 0x91009191, 0xF700F7F7, 0xB500B5B5, 0xC900C9C9, 0xA200A2A2, 0x8C008C8C, 0xD200D2D2, 0x90009090, 0xF600F6F6, 0x07000707, 0xA700A7A7, 0x27002727, 0x8E008E8E, 0xB200B2B2, 0x49004949, 0xDE00DEDE, 0x43004343, 0x5C005C5C, 0xD700D7D7, 0xC700C7C7, 0x3E003E3E, 0xF500F5F5, 0x8F008F8F, 0x67006767, 0x1F001F1F, 0x18001818, 0x6E006E6E, 0xAF00AFAF, 0x2F002F2F, 0xE200E2E2, 0x85008585, 0x0D000D0D, 0x53005353, 0xF000F0F0, 0x9C009C9C, 0x65006565, 0xEA00EAEA, 0xA300A3A3, 0xAE00AEAE, 0x9E009E9E, 0xEC00ECEC, 0x80008080, 0x2D002D2D, 0x6B006B6B, 0xA800A8A8, 0x2B002B2B, 0x36003636, 0xA600A6A6, 0xC500C5C5, 0x86008686, 0x4D004D4D, 0x33003333, 0xFD00FDFD, 0x66006666, 0x58005858, 0x96009696, 0x3A003A3A, 0x09000909, 0x95009595, 0x10001010, 0x78007878, 0xD800D8D8, 0x42004242, 0xCC00CCCC, 0xEF00EFEF, 0x26002626, 0xE500E5E5, 0x61006161, 0x1A001A1A, 0x3F003F3F, 0x3B003B3B, 0x82008282, 0xB600B6B6, 0xDB00DBDB, 0xD400D4D4, 0x98009898, 0xE800E8E8, 0x8B008B8B, 0x02000202, 0xEB00EBEB, 0x0A000A0A, 0x2C002C2C, 0x1D001D1D, 0xB000B0B0, 0x6F006F6F, 0x8D008D8D, 0x88008888, 0x0E000E0E, 0x19001919, 0x87008787, 0x4E004E4E, 0x0B000B0B, 0xA900A9A9, 0x0C000C0C, 0x79007979, 0x11001111, 0x7F007F7F, 0x22002222, 0xE700E7E7, 0x59005959, 0xE100E1E1, 0xDA00DADA, 0x3D003D3D, 0xC800C8C8, 0x12001212, 0x04000404, 0x74007474, 0x54005454, 0x30003030, 0x7E007E7E, 0xB400B4B4, 0x28002828, 0x55005555, 0x68006868, 0x50005050, 0xBE00BEBE, 0xD000D0D0, 0xC400C4C4, 0x31003131, 0xCB00CBCB, 0x2A002A2A, 0xAD00ADAD, 0x0F000F0F, 0xCA00CACA, 0x70007070, 0xFF00FFFF, 0x32003232, 0x69006969, 0x08000808, 0x62006262, 0x00000000, 0x24002424, 0xD100D1D1, 0xFB00FBFB, 0xBA00BABA, 0xED00EDED, 0x45004545, 0x81008181, 0x73007373, 0x6D006D6D, 0x84008484, 0x9F009F9F, 0xEE00EEEE, 0x4A004A4A, 0xC300C3C3, 0x2E002E2E, 0xC100C1C1, 0x01000101, 0xE600E6E6, 0x25002525, 0x48004848, 0x99009999, 0xB900B9B9, 0xB300B3B3, 0x7B007B7B, 0xF900F9F9, 0xCE00CECE, 0xBF00BFBF, 0xDF00DFDF, 0x71007171, 0x29002929, 0xCD00CDCD, 0x6C006C6C, 0x13001313, 0x64006464, 0x9B009B9B, 0x63006363, 0x9D009D9D, 0xC000C0C0, 0x4B004B4B, 0xB700B7B7, 0xA500A5A5, 0x89008989, 0x5F005F5F, 0xB100B1B1, 0x17001717, 0xF400F4F4, 0xBC00BCBC, 0xD300D3D3, 0x46004646, 0xCF00CFCF, 0x37003737, 0x5E005E5E, 0x47004747, 0x94009494, 0xFA00FAFA, 0xFC00FCFC, 0x5B005B5B, 0x97009797, 0xFE00FEFE, 0x5A005A5A, 0xAC00ACAC, 0x3C003C3C, 0x4C004C4C, 0x03000303, 0x35003535, 0xF300F3F3, 0x23002323, 0xB800B8B8, 0x5D005D5D, 0x6A006A6A, 0x92009292, 0xD500D5D5, 0x21002121, 0x44004444, 0x51005151, 0xC600C6C6, 0x7D007D7D, 0x39003939, 0x83008383, 0xDC00DCDC, 0xAA00AAAA, 0x7C007C7C, 0x77007777, 0x56005656, 0x05000505, 0x1B001B1B, 0xA400A4A4, 0x15001515, 0x34003434, 0x1E001E1E, 0x1C001C1C, 0xF800F8F8, 0x52005252, 0x20002020, 0x14001414, 0xE900E9E9, 0xBD00BDBD, 0xDD00DDDD, 0xE400E4E4, 0xA100A1A1, 0xE000E0E0, 0x8A008A8A, 0xF100F1F1, 0xD600D6D6, 0x7A007A7A, 0xBB00BBBB, 0xE300E3E3, 0x40004040, 0x4F004F4F])

const SIGMA = new Uint32Array([0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2, 0xC6EF372F, 0xE94F82BE, 0x54FF53A5, 0xF1D36F1C, 0x10E527FA, 0xDE682D1D, 0xB05688C2, 0xB3E6C1FD])

// * Functions

function ROTL128(s: Uint32Array, bit: number) {
  const n = 32 - bit
  const t = s[3] << bit | s[0] >>> n
  s[0] = s[0] << bit | s[1] >>> n
  s[1] = s[1] << bit | s[2] >>> n
  s[2] = s[2] << bit | s[3] >>> n
  s[3] = t
}

function Camellia_Feistel(sh: Uint32Array, sl: Uint32Array, kh: number, kl: number) {
  const t0 = sh[0] ^ kh
  const t1 = sh[1] ^ kl
  const t3
    = SBox1_1110[0xFF & (t0 >> 24)]
    ^ SBox2_0222[0xFF & (t0 >> 16)]
    ^ SBox3_3033[0xFF & (t0 >> 8)]
    ^ SBox4_4404[0xFF & (t0)]
  const t2
    = t3
    ^ SBox1_1110[0xFF & (t1)]
    ^ SBox4_4404[0xFF & (t1 >> 8)]
    ^ SBox3_3033[0xFF & (t1 >> 16)]
    ^ SBox2_0222[0xFF & (t1 >> 24)]
  sl[0] ^= t2
  sl[1] ^= t2 ^ rotateR32(t3, 8)
}

// * Camellia Algorithm

function KeySchedule(K: Uint8Array) {
  const KView = new DataView(K.buffer)
  const k = K.length === 16 ? new Uint32Array(52) : new Uint32Array(68)
  const s = new Uint32Array(4)
  const sh = s.subarray(0, 2)
  const sl = s.subarray(2, 4)

  /* Map the key to the keyTable */
  switch (K.length) {
    case 16:
      mapKey128(KView, s, k)
      break
    case 24:
      mapKey192(KView, s, k)
      break
    case 32:
      mapKey256(KView, s, k)
      break
  }

  /* Use the Feistel routine to scramble the key material */
  Camellia_Feistel(sh, sl, SIGMA[0], SIGMA[1])
  Camellia_Feistel(sl, sh, SIGMA[2], SIGMA[3])

  s[0] ^= k[0]; s[1] ^= k[1]; s[2] ^= k[2]; s[3] ^= k[3]
  Camellia_Feistel(sh, sl, SIGMA[4], SIGMA[5])
  Camellia_Feistel(sl, sh, SIGMA[6], SIGMA[7])

  /* Fill the keyTable. Requires many block rotations. */
  switch (K.length) {
    case 16:
      setup128(s, k)
      break
    case 24:
    case 32:
      setup256(s, k)
      break
  }

  return k
}
function mapKey128(KView: DataView, s: Uint32Array, k: Uint32Array) {
  s[0] = k[0] = KView.getUint32(0, false)
  s[1] = k[1] = KView.getUint32(4, false)
  s[2] = k[2] = KView.getUint32(8, false)
  s[3] = k[3] = KView.getUint32(12, false)
}
function mapKey192(KView: DataView, s: Uint32Array, k: Uint32Array) {
  mapKey128(KView, s, k)
  s[0] = k[8] = KView.getUint32(16, false)
  s[1] = k[9] = KView.getUint32(20, false)
  s[2] = k[10] = ~s[0]
  s[3] = k[11] = ~s[1]
  s[0] ^= k[0]; s[1] ^= k[1]; s[2] ^= k[2]; s[3] ^= k[3]
}
function mapKey256(KView: DataView, s: Uint32Array, k: Uint32Array) {
  mapKey192(KView, s, k)
  s[0] = k[8] = KView.getUint32(16, false)
  s[1] = k[9] = KView.getUint32(20, false)
  s[2] = k[10] = KView.getUint32(24, false)
  s[3] = k[11] = KView.getUint32(28, false)
  s[0] ^= k[0]; s[1] ^= k[1]; s[2] ^= k[2]; s[3] ^= k[3]
}
function setup128(s: Uint32Array, k: Uint32Array) {
  k[4] = s[0]; k[5] = s[1]; k[6] = s[2]; k[7] = s[3]
  ROTL128(s, 15) /* KA <<< 15 */
  k[12] = s[0]; k[13] = s[1]; k[14] = s[2]; k[15] = s[3]
  ROTL128(s, 15) /* KA <<< 30 */
  k[16] = s[0]; k[17] = s[1]; k[18] = s[2]; k[19] = s[3]
  ROTL128(s, 15) /* KA <<< 45 */
  k[24] = s[0]; k[25] = s[1]
  ROTL128(s, 15) /* KA <<< 60 */
  k[28] = s[0]; k[29] = s[1]; k[30] = s[2]; k[31] = s[3];
  [s[0], s[1], s[2], s[3]] = [s[1], s[2], s[3], s[0]]
  ROTL128(s, 2) /* KA <<< 94 */
  k[40] = s[0]; k[41] = s[1]; k[42] = s[2]; k[43] = s[3]
  ROTL128(s, 17) /* KA <<<111 */
  k[48] = s[0]; k[49] = s[1]; k[50] = s[2]; k[51] = s[3]

  s[0] = k[0]; s[1] = k[1]; s[2] = k[2]; s[3] = k[3]
  ROTL128(s, 15) /* KL <<< 15 */
  k[8] = s[0]; k[9] = s[1]; k[10] = s[2]; k[11] = s[3]
  ROTL128(s, 30) /* KL <<< 45 */
  k[20] = s[0]; k[21] = s[1]; k[22] = s[2]; k[23] = s[3]
  ROTL128(s, 15) /* KL <<< 60 */
  k[26] = s[2]; k[27] = s[3]
  ROTL128(s, 17) /* KL <<< 77 */
  k[32] = s[0]; k[33] = s[1]; k[34] = s[2]; k[35] = s[3]
  ROTL128(s, 17) /* KL <<< 94 */
  k[36] = s[0]; k[37] = s[1]; k[38] = s[2]; k[39] = s[3]
  ROTL128(s, 17) /* KL <<<111 */
  k[44] = s[0]; k[45] = s[1]; k[46] = s[2]; k[47] = s[3]
}
function setup256(s: Uint32Array, k: Uint32Array) {
  const sh = s.subarray(0, 2)
  const sl = s.subarray(2, 4)
  k[12] = s[0]; k[13] = s[1]; k[14] = s[2]; k[15] = s[3]
  s[0] ^= k[8]; s[1] ^= k[9]; s[2] ^= k[10]; s[3] ^= k[11]
  Camellia_Feistel(sh, sl, SIGMA[8], SIGMA[9])
  Camellia_Feistel(sl, sh, SIGMA[10], SIGMA[11])

  k[4] = s[0]; k[5] = s[1]; k[6] = s[2]; k[7] = s[3]
  ROTL128(s, 30) /* KB <<< 30 */
  k[20] = s[0]; k[21] = s[1]; k[22] = s[2]; k[23] = s[3]
  ROTL128(s, 30) /* KB <<< 60 */
  k[40] = s[0]; k[41] = s[1]; k[42] = s[2]; k[43] = s[3];
  [s[0], s[1], s[2], s[3]] = [s[1], s[2], s[3], s[0]]
  ROTL128(s, 19) /* KB <<<111 */
  k[64] = s[0]; k[65] = s[1]; k[66] = s[2]; k[67] = s[3]

  s[0] = k[8]; s[1] = k[9]; s[2] = k[10]; s[3] = k[11]
  ROTL128(s, 15) /* KR <<< 15 */
  k[8] = s[0]; k[9] = s[1]; k[10] = s[2]; k[11] = s[3]
  ROTL128(s, 15) /* KR <<< 30 */
  k[16] = s[0]; k[17] = s[1]; k[18] = s[2]; k[19] = s[3]
  ROTL128(s, 30) /* KR <<< 60 */
  k[36] = s[0]; k[37] = s[1]; k[38] = s[2]; k[39] = s[3];
  [s[0], s[1], s[2], s[3]] = [s[1], s[2], s[3], s[0]]
  ROTL128(s, 2) /* KR <<< 94 */
  k[52] = s[0]; k[53] = s[1]; k[54] = s[2]; k[55] = s[3]

  s[0] = k[12]; s[1] = k[13]; s[2] = k[14]; s[3] = k[15]
  ROTL128(s, 15) /* KA <<< 15 */
  k[12] = s[0]; k[13] = s[1]; k[14] = s[2]; k[15] = s[3]
  ROTL128(s, 30) /* KA <<< 45 */
  k[28] = s[0]; k[29] = s[1]; k[30] = s[2]; k[31] = s[3]
  /* KA <<< 77 */
  k[48] = s[1]; k[49] = s[2]; k[50] = s[3]; k[51] = s[0];
  [s[0], s[1], s[2], s[3]] = [s[1], s[2], s[3], s[0]]
  ROTL128(s, 17) /* KA <<< 94 */
  k[56] = s[0]; k[57] = s[1]; k[58] = s[2]; k[59] = s[3]

  s[0] = k[0]; s[1] = k[1]; s[2] = k[2]; s[3] = k[3];
  [s[0], s[1], s[2], s[3]] = [s[1], s[2], s[3], s[0]]
  ROTL128(s, 13) /* KL <<< 45 */
  k[24] = s[0]; k[25] = s[1]; k[26] = s[2]; k[27] = s[3]
  ROTL128(s, 15) /* KL <<< 60 */
  k[32] = s[0]; k[33] = s[1]; k[34] = s[2]; k[35] = s[3]
  ROTL128(s, 17) /* KL <<< 77 */
  k[44] = s[0]; k[45] = s[1]; k[46] = s[2]; k[47] = s[3];
  [s[0], s[1], s[2], s[3]] = [s[1], s[2], s[3], s[0]]
  ROTL128(s, 2) /* KL <<<111 */
  k[60] = s[0]; k[61] = s[1]; k[62] = s[2]; k[63] = s[3]
}

function _encrypt128(M: Uint8Array, k: Uint32Array) {
  const C = M.slice(0)
  const CView = new DataView(C.buffer)
  const s = new Uint32Array(4)
  const sh = s.subarray(0, 2)
  const sl = s.subarray(2, 4)
  s[0] = k[0] ^ CView.getUint32(0, false)
  s[1] = k[1] ^ CView.getUint32(4, false)
  s[2] = k[2] ^ CView.getUint32(8, false)
  s[3] = k[3] ^ CView.getUint32(12, false)

  // GR 1
  Camellia_Feistel(sh, sl, k[4], k[5])
  Camellia_Feistel(sl, sh, k[6], k[7])
  Camellia_Feistel(sh, sl, k[8], k[9])
  Camellia_Feistel(sl, sh, k[10], k[11])
  Camellia_Feistel(sh, sl, k[12], k[13])
  Camellia_Feistel(sl, sh, k[14], k[15])
  s[1] ^= rotateL32(s[0] & k[16], 1)
  s[2] ^= s[3] | k[19]
  s[0] ^= s[1] | k[17]
  s[3] ^= rotateL32(s[2] & k[18], 1)
  // GR 2
  Camellia_Feistel(sh, sl, k[20], k[21])
  Camellia_Feistel(sl, sh, k[22], k[23])
  Camellia_Feistel(sh, sl, k[24], k[25])
  Camellia_Feistel(sl, sh, k[26], k[27])
  Camellia_Feistel(sh, sl, k[28], k[29])
  Camellia_Feistel(sl, sh, k[30], k[31])
  s[1] ^= rotateL32(s[0] & k[32], 1)
  s[2] ^= s[3] | k[35]
  s[0] ^= s[1] | k[33]
  s[3] ^= rotateL32(s[2] & k[34], 1)
  // GR 3
  Camellia_Feistel(sh, sl, k[36], k[37])
  Camellia_Feistel(sl, sh, k[38], k[39])
  Camellia_Feistel(sh, sl, k[40], k[41])
  Camellia_Feistel(sl, sh, k[42], k[43])
  Camellia_Feistel(sh, sl, k[44], k[45])
  Camellia_Feistel(sl, sh, k[46], k[47])
  s[2] ^= k[48]
  s[3] ^= k[49]
  s[0] ^= k[50]
  s[1] ^= k[51]

  CView.setUint32(0, s[2], false)
  CView.setUint32(4, s[3], false)
  CView.setUint32(8, s[0], false)
  CView.setUint32(12, s[1], false)
  return C
}
function _encrypt256(M: Uint8Array, k: Uint32Array) {
  const C = M.slice(0)
  const CView = new DataView(C.buffer)
  const s = new Uint32Array(4)
  const sh = s.subarray(0, 2)
  const sl = s.subarray(2, 4)
  s[0] = k[0] ^ CView.getUint32(0, false)
  s[1] = k[1] ^ CView.getUint32(4, false)
  s[2] = k[2] ^ CView.getUint32(8, false)
  s[3] = k[3] ^ CView.getUint32(12, false)

  // GR 1
  Camellia_Feistel(sh, sl, k[4], k[5])
  Camellia_Feistel(sl, sh, k[6], k[7])
  Camellia_Feistel(sh, sl, k[8], k[9])
  Camellia_Feistel(sl, sh, k[10], k[11])
  Camellia_Feistel(sh, sl, k[12], k[13])
  Camellia_Feistel(sl, sh, k[14], k[15])
  s[1] ^= rotateL32(s[0] & k[16], 1)
  s[2] ^= s[3] | k[19]
  s[0] ^= s[1] | k[17]
  s[3] ^= rotateL32(s[2] & k[18], 1)
  // GR 2
  Camellia_Feistel(sh, sl, k[20], k[21])
  Camellia_Feistel(sl, sh, k[22], k[23])
  Camellia_Feistel(sh, sl, k[24], k[25])
  Camellia_Feistel(sl, sh, k[26], k[27])
  Camellia_Feistel(sh, sl, k[28], k[29])
  Camellia_Feistel(sl, sh, k[30], k[31])
  s[1] ^= rotateL32(s[0] & k[32], 1)
  s[2] ^= s[3] | k[35]
  s[0] ^= s[1] | k[33]
  s[3] ^= rotateL32(s[2] & k[34], 1)
  // GR 3
  Camellia_Feistel(sh, sl, k[36], k[37])
  Camellia_Feistel(sl, sh, k[38], k[39])
  Camellia_Feistel(sh, sl, k[40], k[41])
  Camellia_Feistel(sl, sh, k[42], k[43])
  Camellia_Feistel(sh, sl, k[44], k[45])
  Camellia_Feistel(sl, sh, k[46], k[47])
  s[1] ^= rotateL32(s[0] & k[48], 1)
  s[2] ^= s[3] | k[51]
  s[0] ^= s[1] | k[49]
  s[3] ^= rotateL32(s[2] & k[50], 1)
  // GR 4
  Camellia_Feistel(sh, sl, k[52], k[53])
  Camellia_Feistel(sl, sh, k[54], k[55])
  Camellia_Feistel(sh, sl, k[56], k[57])
  Camellia_Feistel(sl, sh, k[58], k[59])
  Camellia_Feistel(sh, sl, k[60], k[61])
  Camellia_Feistel(sl, sh, k[62], k[63])
  s[2] ^= k[64]
  s[3] ^= k[65]
  s[0] ^= k[66]
  s[1] ^= k[67]

  CView.setUint32(0, s[2], false)
  CView.setUint32(4, s[3], false)
  CView.setUint32(8, s[0], false)
  CView.setUint32(12, s[1], false)
  return C
}

function _decrypt128(C: Uint8Array, k: Uint32Array) {
  const M = C.slice(0)
  const MView = new DataView(M.buffer)
  const s = new Uint32Array(4)
  const sh = s.subarray(0, 2)
  const sl = s.subarray(2, 4)

  s[0] = k[48] ^ MView.getUint32(0, false)
  s[1] = k[49] ^ MView.getUint32(4, false)
  s[2] = k[50] ^ MView.getUint32(8, false)
  s[3] = k[51] ^ MView.getUint32(12, false)

  // GR1
  Camellia_Feistel(sh, sl, k[46], k[47])
  Camellia_Feistel(sl, sh, k[44], k[45])
  Camellia_Feistel(sh, sl, k[42], k[43])
  Camellia_Feistel(sl, sh, k[40], k[41])
  Camellia_Feistel(sh, sl, k[38], k[39])
  Camellia_Feistel(sl, sh, k[36], k[37])
  s[1] ^= rotateL32(s[0] & k[34], 1)
  s[2] ^= s[3] | k[33]
  s[0] ^= s[1] | k[35]
  s[3] ^= rotateL32(s[2] & k[32], 1)

  // GR2
  Camellia_Feistel(sh, sl, k[30], k[31])
  Camellia_Feistel(sl, sh, k[28], k[29])
  Camellia_Feistel(sh, sl, k[26], k[27])
  Camellia_Feistel(sl, sh, k[24], k[25])
  Camellia_Feistel(sh, sl, k[22], k[23])
  Camellia_Feistel(sl, sh, k[20], k[21])
  s[1] ^= rotateL32(s[0] & k[18], 1)
  s[2] ^= s[3] | k[17]
  s[0] ^= s[1] | k[19]
  s[3] ^= rotateL32(s[2] & k[16], 1)

  // GR3
  Camellia_Feistel(sh, sl, k[14], k[15])
  Camellia_Feistel(sl, sh, k[12], k[13])
  Camellia_Feistel(sh, sl, k[10], k[11])
  Camellia_Feistel(sl, sh, k[8], k[9])
  Camellia_Feistel(sh, sl, k[6], k[7])
  Camellia_Feistel(sl, sh, k[4], k[5])
  s[2] ^= k[0]
  s[3] ^= k[1]
  s[0] ^= k[2]
  s[1] ^= k[3]

  MView.setUint32(0, s[2], false)
  MView.setUint32(4, s[3], false)
  MView.setUint32(8, s[0], false)
  MView.setUint32(12, s[1], false)
  return M
}
function _decrypt256(C: Uint8Array, k: Uint32Array) {
  const M = C.slice(0)
  const MView = new DataView(M.buffer)
  const s = new Uint32Array(4)
  const sh = s.subarray(0, 2)
  const sl = s.subarray(2, 4)

  s[0] = k[64] ^ MView.getUint32(0, false)
  s[1] = k[65] ^ MView.getUint32(4, false)
  s[2] = k[66] ^ MView.getUint32(8, false)
  s[3] = k[67] ^ MView.getUint32(12, false)

  // GR1
  Camellia_Feistel(sh, sl, k[62], k[63])
  Camellia_Feistel(sl, sh, k[60], k[61])
  Camellia_Feistel(sh, sl, k[58], k[59])
  Camellia_Feistel(sl, sh, k[56], k[57])
  Camellia_Feistel(sh, sl, k[54], k[55])
  Camellia_Feistel(sl, sh, k[52], k[53])
  s[1] ^= rotateL32(s[0] & k[50], 1)
  s[2] ^= s[3] | k[49]
  s[0] ^= s[1] | k[51]
  s[3] ^= rotateL32(s[2] & k[48], 1)

  // GR2
  Camellia_Feistel(sh, sl, k[46], k[47])
  Camellia_Feistel(sl, sh, k[44], k[45])
  Camellia_Feistel(sh, sl, k[42], k[43])
  Camellia_Feistel(sl, sh, k[40], k[41])
  Camellia_Feistel(sh, sl, k[38], k[39])
  Camellia_Feistel(sl, sh, k[36], k[37])
  s[1] ^= rotateL32(s[0] & k[34], 1)
  s[2] ^= s[3] | k[33]
  s[0] ^= s[1] | k[35]
  s[3] ^= rotateL32(s[2] & k[32], 1)

  // GR3
  Camellia_Feistel(sh, sl, k[30], k[31])
  Camellia_Feistel(sl, sh, k[28], k[29])
  Camellia_Feistel(sh, sl, k[26], k[27])
  Camellia_Feistel(sl, sh, k[24], k[25])
  Camellia_Feistel(sh, sl, k[22], k[23])
  Camellia_Feistel(sl, sh, k[20], k[21])
  s[1] ^= rotateL32(s[0] & k[18], 1)
  s[2] ^= s[3] | k[17]
  s[0] ^= s[1] | k[19]
  s[3] ^= rotateL32(s[2] & k[16], 1)

  // GR4
  Camellia_Feistel(sh, sl, k[14], k[15])
  Camellia_Feistel(sl, sh, k[12], k[13])
  Camellia_Feistel(sh, sl, k[10], k[11])
  Camellia_Feistel(sl, sh, k[8], k[9])
  Camellia_Feistel(sh, sl, k[6], k[7])
  Camellia_Feistel(sl, sh, k[4], k[5])
  s[2] ^= k[0]
  s[3] ^= k[1]
  s[0] ^= k[2]
  s[1] ^= k[3]

  MView.setUint32(0, s[2], false)
  MView.setUint32(4, s[3], false)
  MView.setUint32(8, s[0], false)
  MView.setUint32(12, s[1], false)
  return M
}

function cipher(M: Uint8Array, k: Uint32Array, _cipher: typeof _encrypt128) {
  if (M.length !== 16) {
    throw new KitError('Camellia block must be 16 byte')
  }
  return new U8(_cipher(M, k))
}

function _camellia(key: Uint8Array, b: 128 | 192 | 256) {
  if (key.length !== b >>> 3) {
    throw new KitError(`Camellia-${b} key must be ${b >>> 3} byte`)
  }
  const K = KeySchedule(key)
  const encrypt = b === 128
    ? (M: Uint8Array) => cipher(M, K, _encrypt128)
    : (M: Uint8Array) => cipher(M, K, _encrypt256)
  const decrypt = b === 128
    ? (C: Uint8Array) => cipher(C, K, _decrypt128)
    : (C: Uint8Array) => cipher(C, K, _decrypt256)
  return { encrypt, decrypt }
}

/**
 * Camellia 分组密码算法 / block cipher algorithm
 *
 * @param {128 | 192 | 256} b - 密钥长度 / Key size (bit)
 */
export function camellia(b: 128 | 192 | 256) {
  return createCipher(
    (K: Uint8Array) => _camellia(K, b),
    {
      ALGORITHM: `Camellia-${b}`,
      BLOCK_SIZE: 16,
      KEY_SIZE: b >>> 3,
      MIN_KEY_SIZE: b >>> 3,
      MAX_KEY_SIZE: b >>> 3,
    },
  )
}
