# Android-源码-bindService-Proxy

## 整体流程

![total](./total.jpg)

一般我们都是在自定义的Applicaiton、Activity或Service中调用bindService()方法。bindService()是一个定义在Context.java类中的抽象方法，在ContextWrapper.java类中实现。Applicaiton、Activity和Service都继承至ContextWrapper。但ContextWrapper并没有干具体的活，而只是把活交给了成员变量mBase:Context的bindService()去处理。mBase具体的类型是ContextImpl.java。ContextImpl中的bindService()则调用了自己的私有方法bindServiceCommon()进行了具体的处理。   

```
@Override
public boolean bindService(Intent service, ServiceConnection conn,
        int flags) {
    return mBase.bindService(service, conn, flags);
}

@Override
public boolean bindService(Intent service, ServiceConnection conn,
        int flags) {
    warnIfCallingFromSystemProcess();
    return bindServiceCommon(service, conn, flags, mMainThread.getHandler(),
            Process.myUserHandle());
}

private boolean bindServiceCommon(Intent service, ServiceConnection conn, int flags, Handler
        handler, UserHandle user) {
    // Keep this in sync with DevicePolicyManager.bindDeviceAdminServiceAsUser.
    IServiceConnection sd;
    if (conn == null) {
        throw new IllegalArgumentException("connection is null");
    }
    if (mPackageInfo != null) {
        sd = mPackageInfo.getServiceDispatcher(conn, getOuterContext(), handler, flags);
    } else {
        throw new RuntimeException("Not supported in system context");
    }
    validateServiceIntent(service);
    try {
        IBinder token = getActivityToken();
        if (token == null && (flags&BIND_AUTO_CREATE) == 0 && mPackageInfo != null
                && mPackageInfo.getApplicationInfo().targetSdkVersion
                < android.os.Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            flags |= BIND_WAIVE_PRIORITY;
        }
        service.prepareToLeaveProcess(this);
        int res = ActivityManager.getService().bindService(
            mMainThread.getApplicationThread(), getActivityToken(), service,
            service.resolveTypeIfNeeded(getContentResolver()),
            sd, flags, getOpPackageName(), user.getIdentifier());
        if (res < 0) {
            throw new SecurityException(
                    "Not allowed to bind to service " + service);
        }
        return res != 0;
    } catch (RemoteException e) {
        throw e.rethrowFromSystemServer();
    }
}
```
bindServiceCommon()除了做一些简单的校验外，主要是获取IActivityManager.java的实例，然后把bindService的工作交给它进行处理。具体的工作是通过Binder机制，通过IPC调用来完成的。关于Binder机制，我们在其他文章再详谈。

回顾一下，bindService整体调用流程还是非常简单的，整体流程如下：  

- ContextWrapper.bindService(service,conn,flags) ->    
- ContextImpl.bindService(service,conn,flags) ->    
- ContextImpl.bindServiceCommon(service,conn,flags,mMainThread.getHandler(),getUser()) ->   
- IActivityManager.bindService(mMainThread.getApplicationThread(),getActivityToken(),service,service.resolveTypeIfNeeded(getContentResolver())

## IActivityManager的具体类型是什么？

![IActivityManager](./IActivityManager.jpg)

通过调用ActivityManager.java的静态方法ActivityManager.getService()来获取IActivityManager的实例。

```
public static IActivityManager getService() {
    return IActivityManagerSingleton.get();
}
```

getService()中调用静态单例IActivityManagerSingleton.get()，get()方法又会调用到该单例的create()方法。create()方法中通过调用ServiceManager.java的静态方法ServiceManager.getService(Context.ACTIVITY_SERVICE)来获取一个IBinder的对象，然后再通过IActivityManager.Stub.java的静态方法asInterface(binder)把这个IBinder对象转换成了一个IActivityManager实例。了解过Binder机制或AIDL的同学，看到这个Stub应该就很熟悉了，这个不是bindservice流程的重点，不做展开。

```
private static final Singleton<IActivityManager> IActivityManagerSingleton =
        new Singleton<IActivityManager>() {
            @Override
            protected IActivityManager create() {
                final IBinder b = ServiceManager.getService(Context.ACTIVITY_SERVICE);
                final IActivityManager am = IActivityManager.Stub.asInterface(b);
                return am;
            }
        };
        
public static android.app.IActivityManager asInterface(android.os.IBinder obj)
{
	if ((obj==null)) {
	return null;
	}
	android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
	if (((iin!=null)&&(iin instanceof android.app.IActivityManager))) {
	return ((android.app.IActivityManager)iin);
	}
	return new android.app.IActivityManager.Stub.Proxy(obj);
}
```

到这里我们就已经挖到IActivityManager具体类型是什么了，是通过new android.app.IActivityManager.Stub.Proxy(iBinder)创建出来的。整个流程我们看到很多静态方法和单例，各位同学可以思考一下Android为什么要这么设计。

回顾一下，获取IActivityManager实例的调用流程如下：  

- iActivityManager = ActivityManger.getService() ->    
- iActivityManager = IActivityManagerSingleton.get() ->    
- iActivityManager = IActivityManagerSingleton.create() ->   
- iBinder = ServiceManager.getService(Context.ACTIVITY_SERVICE) ->  
- iActivityManager = IActivityManager.Stub.asInterface(iBinder) -> 
- iActivityManager = new IActivityMAnaget.Stub.Proxy(binder)

## IBinder的具体类型是什么？
![iBinder](./iBinder.jpg)

通过ServiceManager.getService(Context.ACTIVITY_SERVICE)获取的iBinder的具体类型是什么？

ServiceManager.getService(name)方法，会优先从缓存中找，找不到再调用Binder.allowBlocking(rawGetService(name))，既然叫做缓存嘛，第一次执行时肯定是不存在的。所以第一执行的会走Binder.allowBlocking(rawGetService(name))这个分支。Binder.allowBlocking()只是设置一下标志位，主要的处理逻辑在静态方法rawGetService(name)中。

```
public static IBinder getService(String name) {
    try {
        IBinder service = sCache.get(name);
        if (service != null) {
            return service;
        } else {
            return Binder.allowBlocking(rawGetService(name));
        }
    } catch (RemoteException e) {
        Log.e(TAG, "error in getService", e);
    }
    return null;
}
```

rawGetService(name)中调用了静态方法getIServiceManager()，getIServiceManager()中通过调用ServiceManagerNativie.asIterFace(iBinder)来创建一个单例的ServiceManagerProxy对象。

```
private static IBinder rawGetService(String name) throws RemoteException {
    ...
    final IBinder binder = getIServiceManager().getService(name);
    ...    
    return binder;
}

private static IServiceManager getIServiceManager() {
    if (sServiceManager != null) {
        return sServiceManager;
    }

    // Find the service manager
    sServiceManager = ServiceManagerNative
            .asInterface(Binder.allowBlocking(BinderInternal.getContextObject()));
    return sServiceManager;
}

public static IServiceManager asInterface(IBinder obj) {
    if (obj == null) {
        return null;
    }

    // ServiceManager is never local
    return new ServiceManagerProxy(obj);
}

public ServiceManagerProxy(IBinder remote) {
    mRemote = remote;
    mServiceManager = IServiceManager.Stub.asInterface(remote);
}

public static android.os.IServiceManager asInterface(android.os.IBinder obj)
{
  if ((obj==null)) {
    return null;
  }
  android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
  if (((iin!=null)&&(iin instanceof android.os.IServiceManager))) {
    return ((android.os.IServiceManager)iin);
  }
  return new android.os.IServiceManager.Stub.Proxy(obj);
}

```

是否觉得似成相识，没错这个跟上个章节IActiviyManager.java的asInterface是同一个套路。  
最后通过调用ServiceManagerProxy的getService(name)方法来获取一个IBinder对象，ServiceManagerProxy的getServic中是通过android.os.IServiceManager.Stub.Proxy(obj)来获取IBinder对象。
```
public android.os.IBinder getService(java.lang.String name) throws android.os.RemoteException
{
	android.os.Parcel _data = android.os.Parcel.obtain();
	android.os.Parcel _reply = android.os.Parcel.obtain();
	android.os.IBinder _result;
	try {
	  _data.writeInterfaceToken(DESCRIPTOR);
	  _data.writeString(name);
	  boolean _status = mRemote.transact(Stub.TRANSACTION_getService, _data, _reply, 0);
	  if (!_status && getDefaultImpl() != null) {
	    return getDefaultImpl().getService(name);
	  }
	  _reply.readException();
	  _result = _reply.readStrongBinder();
	}
	finally {
	  _reply.recycle();
	  _data.recycle();
	}
	return _result;
}
```

这里就是Android Binder的机制了，到此为止，在另外的文章我们再详谈。我们这里讨论一个点，IPC通讯，你总的要有个凭证，要不我怎么知道你要跟谁通讯。这就得关注回到了我们实例IServiceManager对象时的入参了。

先回顾一下，获取IBinder的调用流程如下：  
iBinder  = ServiceManager.getService(Context.ACTIVITY_SERVICE) ->
iBinder = ServiceManager.rawGetService(Context.ACTIVITY_SERVICE) ->
iServiceManager = ServiceManager.getIServiceManager() ->
iBinderServiceManager = Binder.allowBlocking(BinderInternal.getContextObject())
iServiceManager = ServiceManagerNative.asInterface(iBinderServiceManager) ->
iServiceManager = new ServiceManagerProxy(iBinderServiceManager) ->
mServiceManager = IServiceManager.Stub.asInterface(Binder.allowBlocking(iBinderServiceManager) ->
iBinder = new android.os.IServiceManager.Stub.Proxy(iBinderServiceManager)


## 实例IServiceManager对象的入参是什么？

![BinderInternal](./BinderInternal.jpg)

时光倒流，让我们回到ServiceManagerNative.asInterface(Binder.allowBlocking(BinderInternal.getContextObject()))，入参是由BinderInternal.getContextObject()创建的一个IBinder对象。getContextObject()是一个natvie方法,对应android_util_binder.cpp的android_os_BinderInternal_getContextObject()方法。

```
static const JNINativeMethod gBinderInternalMethods[] = {
     /* name, signature, funcPtr */
    { "getContextObject", "()Landroid/os/IBinder;", (void*)android_os_BinderInternal_getContextObject },
    ...
}
```

android_os_BinderInternal_getContextObject()中通过调用了ProcessState::self()->getContextObject(NULL)获取一个单例的ProcessState对象，然后再调用该对象的getContextObject(NULL)。


```
static jobject android_os_BinderInternal_getContextObject(JNIEnv* env, jobject clazz)
{
    sp<IBinder> b = ProcessState::self()->getContextObject(NULL);
    return javaObjectForIBinder(env, b);
}

sp<ProcessState> ProcessState::self()
{
    Mutex::Autolock _l(gProcessMutex);
    if (gProcess != nullptr) {
        return gProcess;
    }
    gProcess = new ProcessState(kDefaultDriver);
    return gProcess;
}
```

getContextObject(NULL)中又调用了getStrongProxyForHandle(0)，注意入参是0，这个0在整个Binder机制都是一个特殊的存在。

```
sp<IBinder> ProcessState::getStrongProxyForHandle(int32_t handle)
{
    sp<IBinder> result;
    AutoMutex _l(mLock);
    handle_entry* e = lookupHandleLocked(handle);
    if (e != nullptr) {
        // We need to create a new BpBinder if there isn't currently one, OR we
        // are unable to acquire a weak reference on this current one.  The
        // attemptIncWeak() is safe because we know the BpBinder destructor will always
        // call expungeHandle(), which acquires the same lock we are holding now.
        // We need to do this because there is a race condition between someone
        // releasing a reference on this BpBinder, and a new reference on its handle
        // arriving from the driver.
        IBinder* b = e->binder;
        if (b == nullptr || !e->refs->attemptIncWeak(this)) {
            if (handle == 0) {
                // Special case for context manager...
                // The context manager is the only object for which we create
                // a BpBinder proxy without already holding a reference.
                // Perform a dummy transaction to ensure the context manager
                // is registered before we create the first local reference
                // to it (which will occur when creating the BpBinder).
                // If a local reference is created for the BpBinder when the
                // context manager is not present, the driver will fail to
                // provide a reference to the context manager, but the
                // driver API does not return status.
                //
                // Note that this is not race-free if the context manager
                // dies while this code runs.
                //
                // TODO: add a driver API to wait for context manager, or
                // stop special casing handle 0 for context manager and add
                // a driver API to get a handle to the context manager with
                // proper reference counting.

                Parcel data;
                status_t status = IPCThreadState::self()->transact(
                        0, IBinder::PING_TRANSACTION, data, nullptr, 0);
                if (status == DEAD_OBJECT)
                   return nullptr;
            }

            b = BpBinder::create(handle);
            e->binder = b;
            if (b) e->refs = b->getWeakRefs();
            result = b;
        } else {
            // This little bit of nastyness is to allow us to add a primary
            // reference to the remote proxy when this team doesn't have one
            // but another team is sending the handle to us.
            result.force_set(b);
            e->refs->decWeak(this);
        }
    }
    
    return result;
}
```

可以看到具柄为0时做了一些特殊处理，这就是传说的写死的代码，还是个写死的魔数。还好加了一堆注释。这里通过IPCThreadState::self()创建一个线程单例IPCThreadState对象，然后调用它的transact(0, IBinder::PING_TRANSACTION, data, nullptr, 0)来ping一下，看下context manager是死是活。这个context manager在整个Binder机制又是一个神一样的存在，不在此展开。context manager如果死掉了，那就直接返回个空指针，因为这时无法进行Binder通讯了。活着就通过BpBinder::create(handle)创建一个IBinder对象返回去。

```
IPCThreadState* IPCThreadState::self()
{
    if (gHaveTLS.load(std::memory_order_acquire)) {
restart:
        const pthread_key_t k = gTLS;
        IPCThreadState* st = (IPCThreadState*)pthread_getspecific(k);
        if (st) return st;
        return new IPCThreadState;
    }

    // Racey, heuristic test for simultaneous shutdown.
    if (gShutdown.load(std::memory_order_relaxed)) {
        ALOGW("Calling IPCThreadState::self() during shutdown is dangerous, expect a crash.\n");
        return nullptr;
    }

    pthread_mutex_lock(&gTLSMutex);
    if (!gHaveTLS.load(std::memory_order_relaxed)) {
        int key_create_value = pthread_key_create(&gTLS, threadDestructor);
        if (key_create_value != 0) {
            pthread_mutex_unlock(&gTLSMutex);
            ALOGW("IPCThreadState::self() unable to create TLS key, expect a crash: %s\n",
                    strerror(key_create_value));
            return nullptr;
        }
        gHaveTLS.store(true, std::memory_order_release);
    }
    pthread_mutex_unlock(&gTLSMutex);
    goto restart;
}

BpBinder* BpBinder::create(int32_t handle) {
    int32_t trackedUid = -1;
    if (sCountByUidEnabled) {
        trackedUid = IPCThreadState::self()->getCallingUid();
        AutoMutex _l(sTrackingLock);
        uint32_t trackedValue = sTrackingMap[trackedUid];
        if (CC_UNLIKELY(trackedValue & LIMIT_REACHED_MASK)) {
            if (sBinderProxyThrottleCreate) {
                return nullptr;
            }
        } else {
            if ((trackedValue & COUNTING_VALUE_MASK) >= sBinderProxyCountHighWatermark) {
                ALOGE("Too many binder proxy objects sent to uid %d from uid %d (%d proxies held)",
                      getuid(), trackedUid, trackedValue);
                sTrackingMap[trackedUid] |= LIMIT_REACHED_MASK;
                if (sLimitCallback) sLimitCallback(trackedUid);
                if (sBinderProxyThrottleCreate) {
                    ALOGI("Throttling binder proxy creates from uid %d in uid %d until binder proxy"
                          " count drops below %d",
                          trackedUid, getuid(), sBinderProxyCountLowWatermark);
                    return nullptr;
                }
            }
        }
        sTrackingMap[trackedUid]++;
    }
    return new BpBinder(handle, trackedUid);
}
```

到这里我们就搞清楚实例IServiceManager对象的入参是什么了，是一个具柄为0的BpBinder对象。

回顾一下，获取IServiceManager入参的的BpBinder对象的调用流程如下：

iBinder = BinderInternal.getContextObject() ->  
iBinder = android_utl_binder.cpp android_os_BinderInternal_getContextObject() ->  
gProcess = ProcessState::self() ->  
iBinder = gProcess->getContextObject(NULL) ->  
iBinder = ProcessState::getStrongProxyForHandle(0) ->  
IPCThreadState::self()->transact(0, IBinder::PING_TRANSACTION, data, nullptr, 0) ->
iBinder = BpBinder::create(0)

## 捋一捋

最后我们把前面的内容全部串起来，如下： 
ContextWrapper.bindService(service,conn,flags) ->    
ContextImpl.bindService(service,conn,flags) ->    
ContextImpl.bindServiceCommon(service,conn,flags,mMainThread.getHandler(),getUser()) ->   
amProxy = ActivityManger.getService() ->      
amProxy = IActivityManagerSingleton.get() ->      
amProxy = IActivityManagerSingleton.create ->     
iBinderAMProxy = ServiceManager.getService(Context.ACTIVITY_SERVICE) ->    
iBinderAMProxy = ServiceManager.rawGetService(Context.ACTIVITY_SERVICE) ->    
smProxy = ServiceManager.getIServiceManager() ->  
bpBinderSMProxy = BinderInternal.getContextObject() ->    
bpBinderSMProxy  = android_utl_binder.cpp android_os_BinderInternal_getContextObject() ->      
gProcessState = ProcessState::self() ->    
bpBinderSMProxy  = gProcessState->getContextObject(NULL) ->    
bpBinderSMProxy  = ProcessState::getStrongProxyForHandle(0) ->    
IPCThreadState::self()->transact(0, IBinder::PING_TRANSACTION, data, nullptr, 0) ->  
bpBinderSMProxy  = BpBinder::create(0) ->    
smProxy = ServiceManagerNative.asInterface(bpBinder) ->  
smProxy = new ServiceManagerProxy(bpBinder) ->  
mServiceManager = IServiceManager.Stub.asInterface(bpBinderSMProxy) ->  
mServiceManager = new android.os.IServiceManager.Stub.Proxy(bpBinderSMProxy) ->
amProxy = IActivityManager.Stub.asInterface(iBinderAMProxy) ->   
amProxy = new IActivityMAnaget.Stub.Proxy(iBinderAMProxy) ->  
amProxy.bindService(mMainThread.getApplicationThread(),getActivityToken(),service,service.resolveTypeIfNeeded(getContentResolver())

浓缩成一句话：
bindServie的流程就是，先调用ContextWrapper的bindServiceCommon()方法，获取一个ServiceManager代理，然后使用ServiceManager代理通过Binder IPC的通讯方式获取ActivityManagerService的IBinder对象，通过这个IBinder对象创建ActivityManager本地代理，然后再使用这个本地的ServiceManager代理把bindService的工作通过Binder IPC的方式交给ActivityManagerService去处理。





    
