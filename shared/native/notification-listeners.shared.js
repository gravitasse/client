// @flow
import {ConversationBadgeStateRecord} from '../constants/chat'
import {List} from 'immutable'
import {badgeAppForChat} from '../actions/chat'
import {badgeApp} from '../actions/notifications'
import {bootstrap, updateFollowing} from '../actions/config'
import {logoutDone} from '../actions/login'

import type {Dispatch} from '../constants/types/flux'
import type {incomingCallMapType} from '../constants/types/flow-types'

// Keep track of the last time we notified and ignore if its the same
let lastLoggedInNotifyUsername = null

export default function (dispatch: Dispatch, getState: () => Object, notify: any): incomingCallMapType {
  return {
    'keybase.1.NotifyBadges.badgeState': ({badgeState}) => {
      const {conversations, newTlfs} = badgeState
      const convos = List(conversations.map(conversation => ConversationBadgeStateRecord(conversation)))
      dispatch(badgeAppForChat(convos))
      dispatch(badgeApp('newTLFs', newTlfs > 0, newTlfs))
    },
    'keybase.1.NotifySession.loggedIn': ({username}, response) => {
      if (lastLoggedInNotifyUsername !== username) {
        lastLoggedInNotifyUsername = username
        notify('Logged in to Keybase as: ' + username)
      }

      dispatch(bootstrap())
      response.result()
    },
    'keybase.1.NotifySession.loggedOut': params => {
      lastLoggedInNotifyUsername = null

      // Do we actually think we're logged in?
      if (getState().config &&
        getState().config.status &&
        getState().config.status.loggedIn) {
        notify('Logged out of Keybase')
        dispatch(logoutDone())
      }
    },
    'keybase.1.NotifyTracking.trackingChanged': ({username, isTracking}) => {
      dispatch(updateFollowing(username, isTracking))
    },
  }
}
