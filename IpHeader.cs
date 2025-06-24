using System;
using System.IO;
using System.Net;

namespace Packet;

/// <summary>
/// The IpHeader class defines a direct representation of the IPv4 header structure from RFC 791
/// with no deviations or vendor-specific structure for an IPv4 packet header. 
/// https://www.rfc-editor.org/rfc/rfc791#section-3.1
/// </summary>
public class IpHeader
{
    public string IpVersion
    {
        get
        {
            // 4 bits of an IP header contain version of an IP (v4 or v6)
            return (_versionAndHeaderLength >> 4) switch
            {
                4 => "IP v4",
                6 => "IP v6",
                _ => "Unknown"
            };
        }
    }

    public string DifferentiatedServices =>
        $"0x{_differentServices:x2} ({_differentServices})";

    public string TotalLength => _totalDatagramLength.ToString();

    public string Identification => _identification.ToString();

    public string Flags
    {
        get
        {
            var nFlags = _flagsAndOffset >> 13;
            return nFlags switch
            {
                2 => "Don't fragment",
                1 => "More fragments to come",
                _ => nFlags.ToString()
            };
        }
    }

    public string Ttl => _ttl.ToString();

    public string Protocol => _protocol.ToString();

    public string Checksum => $"0x{_checksum:x2}";

    public IPAddress SourceAddress => new(_sourceIpAddress);

    public IPAddress DestinationAddress => new(_destinationIpAddress);

    public string HeaderLength => _headerLength.ToString();

    public ushort MessageLength => (ushort)(_totalDatagramLength - _headerLength);

    public string FragmentationOffset
    {
        get
        {
            var nOffset = _flagsAndOffset & 0x1FFF;
            nOffset >>= 3;
            return nOffset.ToString();
        }
    }

    public byte[] Data { get; private set; }


    public IpHeader(byte[] incomingBuffer, int numberReceived)
    {
        try
        {
            using MemoryStream memoryStream = new(incomingBuffer, 0, numberReceived);
            using BinaryReader binaryReader = new(memoryStream);

            _versionAndHeaderLength = binaryReader.ReadByte();

            _differentServices = binaryReader.ReadByte();

            _totalDatagramLength = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            _identification = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            _flagsAndOffset = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            _ttl = binaryReader.ReadByte();

            _protocol = binaryReader.ReadByte();

            _checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            _sourceIpAddress = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());

            _destinationIpAddress = (uint)binaryReader.ReadInt32();
                
            Data = new byte[_totalDatagramLength - _headerLength];

            // Calculating header's length
            _headerLength = _versionAndHeaderLength;
            _headerLength <<= 4;
            _headerLength >>= 4;
            // Mutiply by 4 to know exact value
            _headerLength *= 4;

            Array.Copy(incomingBuffer,
                _headerLength, //starting to copy from the end of a header
                Data, 0,
                _totalDatagramLength - _headerLength);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }

    // IP Header and its fields
    
    private readonly byte _versionAndHeaderLength; // Version (4 bits) + Internet Header Length (4 bits)

    
    private readonly byte _differentServices; // 8 bit different services 

    
    private readonly ushort _totalDatagramLength; // 16 bit Total Length

    
    private readonly ushort _identification; // 16 bit Identification

    
    private readonly ushort _flagsAndOffset; // Flags (3 bits) + Fragment Offset (13 bits)

   
    private readonly byte _ttl; // 8 bit Time to Live

    private readonly byte _protocol; // 8 bit Protocol

    private readonly short _checksum; // 16 bit Header Checksum

    private readonly uint _sourceIpAddress; // 32 bit Source Address

    private readonly uint _destinationIpAddress; // 32 bit Destination Address

    private readonly byte _headerLength; // 8 bit header length
}