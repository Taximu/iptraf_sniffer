using System;
using System.IO;
using System.Net;

namespace Packet;

/// <summary>
/// IP Header and its fields
/// </summary>
public class IpHeader
{
    public string IpVersion
    {
        get
        {
            //4 bits of an IP header contain version of an IP (v4 or v6)
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
            var nOffset = _flagsAndOffset << 3;
            nOffset >>= 3;
            return nOffset.ToString();
        }
    }

    public byte[] Data { get; } = new byte[4096];


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

            _sourceIpAddress = (uint)(binaryReader.ReadInt32());

            _destinationIpAddress = (uint)(binaryReader.ReadInt32());

            #region Calculating header's length
            _headerLength = _versionAndHeaderLength;
            _headerLength <<= 4;
            _headerLength >>= 4;
            #endregion

            _headerLength *= 4;

            Array.Copy(incomingBuffer,
                _headerLength,
                Data, 0,
                _totalDatagramLength - _headerLength);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
    
    private readonly byte _versionAndHeaderLength;
    private readonly byte _differentServices;
    private readonly ushort _totalDatagramLength;
    private readonly ushort _identification;
    private readonly ushort _flagsAndOffset;
    private readonly byte _ttl;
    private readonly byte _protocol;
    private readonly short _checksum;
    private readonly uint _sourceIpAddress;
    private readonly uint _destinationIpAddress;
    private readonly byte _headerLength;
}