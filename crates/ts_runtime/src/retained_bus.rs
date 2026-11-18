use core::{
    any::{Any, TypeId},
    marker::PhantomData,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::{collections::HashMap, sync::Arc};

use tokio::sync::mpsc;

use kameo::{
    actor::{ActorId, Recipient},
    message::{Context, Message},
};
pub use kameo_actors::message_bus::Register;

/// Type-erased [`SubState<M>`].
type ErasedSubState = Box<dyn Any + Send>;

/// A version of [`MessageBus`][kameo_actor::message_bus::MessageBus] optionally tracking retained
/// state.
///
/// [`Publish`] messages may optionally set the `retained` flag to indicate that the message should
/// be retained on the bus. When present, new [`Register`]ed actors receive the current retained
/// message immediately.
#[derive(Default, kameo::Actor)]
pub struct RetainedBus {
    /// Essentially: `Map<M, SubState<M>>`.
    subscriptions: HashMap<TypeId, ErasedSubState>,
}

// The unwraps in this impl block are safe because they are only present on downcasts, which are
// protected by the invariant that the value type for `TypeId::of::<M>()` is `SubState<M>`.
impl RetainedBus {
    fn get<M>(&self) -> Option<&SubState<M>>
    where
        M: Send + 'static,
    {
        let state = self.subscriptions.get(&TypeId::of::<M>())?;
        Some(state.downcast_ref().unwrap())
    }

    fn get_mut<M>(&mut self) -> Option<&mut SubState<M>>
    where
        M: Send + 'static,
    {
        let state = self.subscriptions.get_mut(&TypeId::of::<M>())?;
        Some(state.downcast_mut().unwrap())
    }

    fn entry_or_default<M>(&mut self) -> &mut SubState<M>
    where
        M: Send + 'static,
    {
        let state = self
            .subscriptions
            .entry(TypeId::of::<M>())
            .or_insert_with(|| Box::new(SubState::<M>::default()));

        state.downcast_mut().unwrap()
    }

    fn remove<M>(&mut self) -> Option<SubState<M>>
    where
        M: Send + 'static,
    {
        let ret = *self
            .subscriptions
            .remove(&TypeId::of::<M>())?
            .downcast::<SubState<M>>()
            .unwrap();

        Some(ret)
    }
}

struct SubState<M>
where
    M: Send + 'static,
{
    retained: Option<M>,
    recipients: HashMap<ActorId, Subscriber<M>>,
}

/// A subscribed actor and the queue of messages on their way to it.
///
/// The bus hands messages to the queue and never waits on the actor's mailbox. Subscribers publish
/// from their own handlers, so a bus that waited on a full subscriber mailbox while that
/// subscriber waited on the full bus mailbox would stop every publisher for good. A task per
/// subscriber delivers its queue in order.
///
/// Unretained messages carry what peers send (disco and STUN packets), so a stalled subscriber
/// holds at most [`UNRETAINED_QUEUE_LIMIT`] queued messages and the rest are dropped; those
/// messages are best-effort and their senders retry. Retained messages are state from control and
/// local actors whose loss would leave the subscriber with a wrong picture, so they always queue.
struct Subscriber<M>
where
    M: Send + 'static,
{
    recipient: Recipient<M>,
    queue: mpsc::UnboundedSender<M>,
    queued: Arc<AtomicUsize>,
}

/// The most messages queued for one subscriber past which unretained messages are dropped.
const UNRETAINED_QUEUE_LIMIT: usize = 256;

/// What became of a message handed to a [`Subscriber`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Queued {
    Yes,
    Dropped,
    Gone,
}

impl<M> Subscriber<M>
where
    M: Send + 'static,
{
    fn new(recipient: Recipient<M>) -> Self {
        let (queue, mut rx) = mpsc::unbounded_channel::<M>();
        let target = recipient.clone();
        let queued = Arc::new(AtomicUsize::new(0));
        let delivered = queued.clone();

        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                delivered.fetch_sub(1, Ordering::Relaxed);
                // The actor stopped; dropping the receiver tells the bus.
                if target.tell(message).await.is_err() {
                    return;
                }
            }
        });

        Self {
            recipient,
            queue,
            queued,
        }
    }

    /// Queues `message`, unless it is unretained and the subscriber is already behind.
    fn send(&self, message: M, retained: bool) -> Queued {
        if !retained && self.queued.load(Ordering::Relaxed) >= UNRETAINED_QUEUE_LIMIT {
            return Queued::Dropped;
        }

        self.queued.fetch_add(1, Ordering::Relaxed);
        if self.queue.send(message).is_ok() {
            Queued::Yes
        } else {
            Queued::Gone
        }
    }

    fn is_alive(&self) -> bool {
        self.recipient.is_alive() && !self.queue.is_closed()
    }
}

impl<M> Default for SubState<M>
where
    M: Send + 'static,
{
    fn default() -> Self {
        Self {
            retained: None,
            recipients: Default::default(),
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct Publish<M> {
    pub message: M,
    pub retained: bool,
}

impl<M> Publish<M> {
    /// Construct a new unretained publish.
    ///
    /// If there exists a retained message stored in the [`RetainedBus`] for this message type, it
    /// is neither updated nor cleared by this message.
    pub const fn unretained(m: M) -> Self {
        Self {
            message: m,
            retained: false,
        }
    }

    /// Construct a new retained publish.
    ///
    /// It will update the retained message in the [`RetainedBus`].
    pub const fn retained(m: M) -> Self {
        Self {
            message: m,
            retained: true,
        }
    }
}

impl<M> Message<Publish<M>> for RetainedBus
where
    M: Clone + Send + 'static,
{
    type Reply = ();

    async fn handle(
        &mut self,
        Publish { message, retained }: Publish<M>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let state = self.entry_or_default::<M>();

        if retained {
            state.retained = Some(message.clone());
        }

        let mut any_missing = false;

        for (id, recip) in &state.recipients {
            match recip.send(message.clone(), retained) {
                Queued::Yes => {}
                Queued::Dropped => tracing::debug!(
                    ?id,
                    msgty = core::any::type_name::<M>(),
                    "subscriber behind, dropping unretained message"
                ),
                // actor is dead (this is an expected case)
                Queued::Gone => any_missing = true,
            }
        }

        if any_missing {
            state.recipients.retain(|id, recip| {
                let retain = recip.is_alive();
                if !retain {
                    tracing::trace!(
                        ?id,
                        msgty = core::any::type_name::<M>(),
                        "actor gone, remove subscription"
                    );
                }

                retain
            });
        }
    }
}

impl<M> Message<Register<M>> for RetainedBus
where
    M: Clone + Send + 'static,
{
    type Reply = Option<Recipient<M>>;

    async fn handle(
        &mut self,
        Register(recip): Register<M>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let state = self.entry_or_default::<M>();

        if let Some(existing) = state.recipients.get(&recip.id()) {
            return Some(existing.recipient.clone());
        }

        let subscriber = Subscriber::new(recip.clone());
        if let Some(retained) = &state.retained
            && subscriber.send(retained.clone(), true) == Queued::Gone
        {
            tracing::error!(id = ?recip.id(), "subscriber gone before its retained message");
        }

        state.recipients.insert(recip.id(), subscriber);
        None
    }
}

/// Get the current retained value for type `M` (if any).
#[derive(Debug, Copy, Clone, Default)]
pub struct GetRetained<M>(PhantomData<M>);

impl<M> Message<GetRetained<M>> for RetainedBus
where
    M: Clone + Send + 'static,
{
    type Reply = Option<M>;

    async fn handle(
        &mut self,
        _: GetRetained<M>,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let state = self.get::<M>()?;
        let ret = state.retained.as_ref()?;

        Some(ret.clone())
    }
}

pub struct Unregister<M> {
    actor_id: ActorId,
    _phantom: PhantomData<M>,
}

impl<M> Unregister<M> {
    pub const fn new(id: ActorId) -> Self {
        Self {
            actor_id: id,
            _phantom: PhantomData,
        }
    }
}

impl<M> Message<Unregister<M>> for RetainedBus
where
    M: Send + 'static,
{
    type Reply = (Option<Recipient<M>>, Option<M>);

    async fn handle(
        &mut self,
        Unregister { actor_id, .. }: Unregister<M>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Some(state) = self.get_mut::<M>() else {
            return (None, None);
        };

        let ret = state.recipients.remove(&actor_id).map(|s| s.recipient);

        let state = if state.recipients.is_empty() {
            self.remove::<M>().and_then(|state| state.retained)
        } else {
            None
        };

        (ret, state)
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use kameo::actor::{ActorRef, Spawn};
    use tokio::sync::oneshot;

    use super::*;

    /// Ensure that the downcasts are of the correct types.
    #[test]
    fn basic() {
        type T = ();

        let mut bus = RetainedBus::default();

        let ent = bus.entry_or_default::<T>();
        assert!(ent.retained.is_none());
        assert!(ent.recipients.is_empty());

        assert!(bus.get::<T>().is_some());
        assert!(bus.get_mut::<T>().is_some());

        let ent = bus.remove::<T>().unwrap();
        assert!(ent.retained.is_none());
        assert!(ent.recipients.is_empty());
    }

    #[tokio::test]
    async fn bus_basic() {
        let bus = RetainedBus::spawn_default();
        bus.wait_for_startup_result().await.unwrap();

        #[derive(kameo::Actor)]
        struct Dummy(Option<oneshot::Sender<()>>);

        #[kameo::messages]
        impl Dummy {
            #[message(ctx)]
            async fn test(&self, bus: ActorRef<RetainedBus>, ctx: &mut Context<Self, ()>) {
                bus.ask(Register(ctx.actor_ref().clone().recipient::<Test2>()))
                    .await
                    .unwrap();

                bus.tell(Publish::unretained(Test2)).try_send().unwrap();
            }

            #[message]
            fn test2(&mut self) {
                self.0.take().unwrap().send(()).unwrap();
            }
        }

        impl Clone for Test2 {
            fn clone(&self) -> Self {
                Self
            }
        }

        let (tx, rx) = oneshot::channel();
        let dummy = Dummy::spawn(Dummy(Some(tx)));
        dummy.ask(Test { bus: bus.clone() }).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .unwrap()
            .unwrap()
    }

    #[derive(Clone)]
    struct Tick;

    #[derive(Clone)]
    struct Tock;

    /// Publishes a [`Tock`] for every [`Tick`] it's sent, as subscribers that derive state do.
    struct Relay {
        bus: ActorRef<RetainedBus>,
        seen: usize,
        want: usize,
        done: Option<oneshot::Sender<()>>,
    }

    impl kameo::Actor for Relay {
        type Args = Self;
        type Error = kameo::error::Infallible;

        async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
            Ok(args)
        }
    }

    impl Message<Tick> for Relay {
        type Reply = ();

        async fn handle(&mut self, _: Tick, _: &mut Context<Self, ()>) {
            self.bus.tell(Publish::retained(Tock)).await.unwrap();
            self.seen += 1;
            if self.seen == self.want
                && let Some(done) = self.done.take()
            {
                let _ = done.send(());
            }
        }
    }

    /// Takes a while over each [`Tick`], as subscribers that probe the network do.
    #[derive(kameo::Actor)]
    struct Slow;

    impl Message<Tick> for Slow {
        type Reply = ();

        async fn handle(&mut self, _: Tick, _: &mut Context<Self, ()>) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_subscriber_that_publishes_does_not_stall_the_bus() {
        const TICKS: usize = 200;

        let bus =
            RetainedBus::spawn_with_mailbox(RetainedBus::default(), kameo::mailbox::bounded(1));
        bus.wait_for_startup().await;

        let (done, finished) = oneshot::channel();
        let relay = Relay::spawn_with_mailbox(
            Relay {
                bus: bus.clone(),
                seen: 0,
                want: TICKS,
                done: Some(done),
            },
            kameo::mailbox::bounded(1),
        );
        relay.wait_for_startup().await;
        bus.ask(Register(relay.clone().recipient::<Tick>()))
            .await
            .unwrap();

        // While the bus waits on this one, publishers fill its mailbox, the relay blocks
        // publishing and its own mailbox fills behind it.
        let slow = Slow::spawn_with_mailbox(Slow, kameo::mailbox::bounded(1));
        slow.wait_for_startup().await;
        bus.ask(Register(slow.recipient::<Tick>())).await.unwrap();

        let publishers = (0..2)
            .map(|_| {
                let bus = bus.clone();
                tokio::spawn(async move {
                    for _ in 0..TICKS / 2 {
                        bus.tell(Publish::retained(Tick)).await.unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();

        tokio::time::timeout(Duration::from_secs(10), finished)
            .await
            .expect("bus and subscriber stalled each other")
            .unwrap();
        for publisher in publishers {
            publisher.await.unwrap();
        }
    }

    /// Never finishes a [`Tick`] until told to.
    struct Stalled(Option<oneshot::Receiver<()>>);

    impl kameo::Actor for Stalled {
        type Args = Self;
        type Error = kameo::error::Infallible;

        async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
            Ok(args)
        }
    }

    impl Message<Tick> for Stalled {
        type Reply = ();

        async fn handle(&mut self, _: Tick, _: &mut Context<Self, ()>) {
            if let Some(release) = self.0.take() {
                let _ = release.await;
            }
        }
    }

    /// Counts its [`Tick`]s.
    #[derive(kameo::Actor)]
    struct Counter(usize);

    impl Message<Tick> for Counter {
        type Reply = usize;

        async fn handle(&mut self, _: Tick, _: &mut Context<Self, usize>) -> usize {
            self.0 += 1;
            self.0
        }
    }

    struct Count;

    impl Message<Count> for Counter {
        type Reply = usize;

        async fn handle(&mut self, _: Count, _: &mut Context<Self, usize>) -> usize {
            self.0
        }
    }

    struct QueuedFor(ActorId);

    impl Message<QueuedFor> for RetainedBus {
        type Reply = usize;

        async fn handle(
            &mut self,
            QueuedFor(id): QueuedFor,
            _: &mut Context<Self, usize>,
        ) -> usize {
            self.get::<Tick>()
                .and_then(|state| state.recipients.get(&id))
                .map_or(0, |sub| sub.queued.load(Ordering::Relaxed))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stalled_subscriber_drops_unretained_messages_and_holds_up_no_one() {
        const TICKS: usize = 4 * UNRETAINED_QUEUE_LIMIT;
        const BATCH: usize = UNRETAINED_QUEUE_LIMIT / 4;

        let bus = RetainedBus::spawn_default();
        bus.wait_for_startup().await;

        let (release, stalled_until) = oneshot::channel();
        let stalled =
            Stalled::spawn_with_mailbox(Stalled(Some(stalled_until)), kameo::mailbox::bounded(1));
        stalled.wait_for_startup().await;
        bus.ask(Register(stalled.clone().recipient::<Tick>()))
            .await
            .unwrap();

        let counter = Counter::spawn(Counter(0));
        counter.wait_for_startup().await;
        bus.ask(Register(counter.clone().recipient::<Tick>()))
            .await
            .unwrap();

        // In batches the healthy subscriber keeps up with, so only the stalled one falls behind.
        for batch in 1..=TICKS / BATCH {
            for _ in 0..BATCH {
                bus.tell(Publish::unretained(Tick)).await.unwrap();
            }

            tokio::time::timeout(Duration::from_secs(10), async {
                while counter.ask(Count).await.unwrap() < batch * BATCH {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("a stalled subscriber held up another");
        }

        assert!(bus.ask(QueuedFor(stalled.id())).await.unwrap() <= UNRETAINED_QUEUE_LIMIT);

        // Retained messages still queue for it, past the limit.
        bus.tell(Publish::retained(Tick)).await.unwrap();
        assert!(bus.ask(QueuedFor(stalled.id())).await.unwrap() > UNRETAINED_QUEUE_LIMIT);

        let _ = release.send(());
    }
}
