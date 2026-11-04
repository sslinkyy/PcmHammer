using PcmHacking;

// Local queues are cleared successfully. A separate scripted upstream delivery
// is deliberately outside that operation's ownership; no hardware port exists.
sealed class DeferredFramePort : IPort
{
    readonly Queue<byte> input=new();
    byte[]? upstream;
    public int Discards { get; private set; }
    public int Sends { get; private set; }
    public void Enqueue(byte[] bytes){foreach(byte value in bytes)input.Enqueue(value);}
    public void ArmUpstream(byte[] bytes)=>upstream=(byte[])bytes.Clone();
    public Task OpenAsync(PortConfiguration configuration)=>throw new Exception("No hardware port may open");
    public Task ChangeBaudRate(int baudRate)=>throw new Exception("No hardware baud change");
    public Task DiscardBuffers(){input.Clear();Discards++;return Task.CompletedTask;}
    public Task Send(byte[] bytes){Sends++;return Task.CompletedTask;}
    public Task<int> GetReceiveQueueSize()
    {
        if(input.Count==0 && upstream!=null){Enqueue(upstream);upstream=null;}
        return input.Count==0?Task.FromException<int>(new TimeoutException("Scripted silence")):Task.FromResult(input.Count);
    }
    public Task<int> Receive(byte[] bytes,int offset,int count)
    {
        if(input.Count<count)throw new Exception("Script requested unavailable bytes");
        for(int i=0;i<count;i++)bytes[offset+i]=input.Dequeue();return Task.FromResult(count);
    }
    public void SetTimeout(int milliseconds){}
    public void Dispose(){}
}
